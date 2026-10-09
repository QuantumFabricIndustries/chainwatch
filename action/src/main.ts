/**
 * ChainWatch GitHub Action entry point.
 *
 * Runs a static scan on node_modules, writes SARIF output, sets action outputs,
 * writes a step summary, and fails the workflow if findings exceed the threshold.
 *
 * When `baseline-file` is provided, the install command runs under the
 * ChainWatch recorder preload (bundled as dist/recorder-preload.mjs) and
 * install-time behavior is diffed against the baseline — this is where
 * postinstall worms fire.
 */

import * as core from '@actions/core';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as zlib from 'node:zlib';
import { pathToFileURL } from 'node:url';
import { execSync } from 'node:child_process';

import { scan } from '../../src/scan/scanner.js';
import { formatSarif } from '../../src/reporter/sarif.js';
import { meetsSeverity, type Finding } from '../../src/scan/finding.js';
import { readBaseline, compactBaseline } from '../../src/baseline/store.js';
import { diffBaseline, type DriftResult } from '../../src/baseline/differ.js';
import type { BaselineEvent } from '../../src/baseline/types.js';
import { parseInputs, type ActionInputs } from './inputs.js';
import { setOutputs, writeSummary } from './outputs.js';

// esbuild emits CJS — __dirname exists in the bundle but isn't declared for ESM types.
declare const __dirname: string;

async function run(): Promise<void> {
  try {
    // 1. Read inputs
    const inputs = parseInputs();
    core.info(`ChainWatch scan: dir=${inputs.scanDir}, severity=${inputs.severity}, fail-on=${inputs.failOn}`);

    // 2. Run install command — monitored when a baseline is provided.
    const baselineEvents = loadBaseline(inputs);
    let driftFindings: Finding[] = [];
    if (inputs.installCommand) {
      if (baselineEvents) {
        driftFindings = runInstallMonitored(inputs, baselineEvents);
      } else {
        core.info(`Running: ${inputs.installCommand}`);
        execSync(inputs.installCommand, { stdio: 'inherit', cwd: process.cwd() });
      }
    }

    // 3. Run static scan
    const scanDir = path.resolve(inputs.scanDir);
    let findings: Finding[] = [];
    let scanMs = 0;
    let packageCount = 0;
    if (fs.existsSync(scanDir)) {
      core.info(`Scanning ${scanDir}...`);
      const result = await scan(scanDir, { minSeverity: inputs.severity });
      findings = result.findings;
      if (inputs.allowPackages.length > 0) {
        const allowed = new Set(inputs.allowPackages);
        const before = findings.length;
        findings = findings.filter((f) => !allowed.has(packageName(f.package)));
        if (before !== findings.length) {
          core.info(`allow-packages: suppressed ${before - findings.length} findings`);
        }
      }
      scanMs = result.scanMs;
      packageCount = result.packageCount;
      core.info(`Scan complete: ${findings.length} findings in ${scanMs}ms (${packageCount} packages)`);
    } else {
      core.warning(`Scan directory does not exist: ${scanDir}`);
      core.info('Skipping static scan — no node_modules found.');
    }

    // 4. Drift findings from the monitored install (if baseline provided).
    if (driftFindings.length > 0) {
      core.info(`Drift detection: ${driftFindings.length} findings above threshold ${inputs.driftThreshold}`);
    }
    const allFindings = [...findings, ...driftFindings];

    // 5. Write SARIF
    const sarifPath = path.resolve(inputs.sarifOutput);
    const sarifDir = path.dirname(sarifPath);
    if (!fs.existsSync(sarifDir)) {
      fs.mkdirSync(sarifDir, { recursive: true });
    }
    fs.writeFileSync(sarifPath, formatSarif(allFindings), 'utf8');
    core.info(`SARIF written to ${sarifPath}`);

    // 6. Upload SARIF to GitHub code scanning if requested.
    if (inputs.uploadSarif) {
      await uploadSarif(sarifPath, inputs);
    }

    // 7. Set outputs + step summary
    setOutputs(allFindings, sarifPath);
    await writeSummary(allFindings);

    // 8. Fail if threshold exceeded
    const shouldFail = allFindings.some((f) => meetsSeverity(f.severity, inputs.failOn));
    if (shouldFail) {
      const critical = allFindings.filter((f) => f.severity === 'critical').length;
      const high = allFindings.filter((f) => f.severity === 'high').length;
      core.setFailed(
        `ChainWatch: ${critical} critical, ${high} high findings detected (fail-on: ${inputs.failOn}).`,
      );
    } else {
      core.info(`ChainWatch: ${allFindings.length} findings, none at or above ${inputs.failOn} severity.`);
    }
  } catch (err) {
    core.setFailed(`ChainWatch action failed: ${(err as Error).message}`);
  }
}

/** "@scope/name@1.2.3" → "@scope/name". */
function packageName(ref: string): string {
  const at = ref.lastIndexOf('@');
  return at > 0 ? ref.slice(0, at) : ref;
}

// ─── Drift detection ────────────────────────────────────────────────────────

/** Load the baseline file if configured. Returns null when not provided. */
function loadBaseline(inputs: ActionInputs): BaselineEvent[] | null {
  if (!inputs.baselineFile) return null;
  const baselinePath = path.resolve(inputs.baselineFile);
  const events = readBaseline(baselinePath);
  if (events.length === 0) {
    core.warning(`baseline-file ${baselinePath} is empty or missing — drift detection disabled.`);
    core.warning('Record one with: chainwatch baseline record -- npm test');
    return null;
  }
  return events;
}

/**
 * Run the install command under the recorder preload and diff the observed
 * behavior against the baseline. Returns drift findings above the threshold.
 */
function runInstallMonitored(inputs: ActionInputs, baselineEvents: BaselineEvent[]): Finding[] {
  const preloadPath = path.resolve(__dirname, 'recorder-preload.mjs');
  if (!fs.existsSync(preloadPath)) {
    core.warning(`recorder-preload.mjs not found at ${preloadPath} — running install unmonitored.`);
    core.info(`Running: ${inputs.installCommand}`);
    execSync(inputs.installCommand, { stdio: 'inherit', cwd: process.cwd() });
    return [];
  }

  const recorderLog = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'chainwatch-action-')),
    'recorder.jsonl',
  );
  const preloadUrl = pathToFileURL(preloadPath).href;

  core.info(`Running (monitored): ${inputs.installCommand}`);
  execSync(inputs.installCommand, {
    stdio: 'inherit',
    cwd: process.cwd(),
    env: {
      ...process.env,
      NODE_OPTIONS: `${process.env['NODE_OPTIONS'] ?? ''} --import ${preloadUrl}`.trim(),
      CHAINWATCH_PRELOAD_URL: preloadUrl,
      CHAINWATCH_RECORDER_LOG: recorderLog,
    },
  });
  // execSync waits for process exit — the preload's exit handler has already
  // flushed remaining events to the recorder log.

  let recorded: BaselineEvent[] = [];
  try {
    recorded = fs.readFileSync(recorderLog, 'utf8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as BaselineEvent);
  } catch {
    core.warning('No recorder events captured from install command.');
  } finally {
    try { fs.rmSync(path.dirname(recorderLog), { recursive: true, force: true }); } catch { /* */ }
  }

  core.info(`Install monitor recorded ${recorded.length} behavioral events.`);
  const baseline = compactBaseline(baselineEvents);
  const results = diffBaseline(recorded, baseline);
  return driftToFindings(results, inputs.driftThreshold);
}

/** Convert drift results above the threshold into findings (CW007). */
export function driftToFindings(results: DriftResult[], threshold: number): Finding[] {
  return results
    .filter((r) => r.driftScore >= threshold)
    .map((r) => ({
      rule: 'behavioral_drift',
      severity: r.severity,
      package: r.pkg,
      description:
        `${r.newEvents.length} new behavior(s) not in baseline: ` +
        r.newEvents.slice(0, 3).map((e) => `${e.signal} ${e.detail}`).join('; ') +
        (r.newEvents.length > 3 ? ` (+${r.newEvents.length - 3} more)` : ''),
      evidence: r.newEvents[0] ? `${r.newEvents[0].signal} → ${r.newEvents[0].detail}` : undefined,
      chainScore: r.driftScore,
    }));
}

// ─── SARIF upload ───────────────────────────────────────────────────────────

/** Upload the SARIF file to GitHub code scanning via the REST API. */
async function uploadSarif(sarifPath: string, inputs: ActionInputs): Promise<void> {
  if (!inputs.githubToken) {
    core.warning('upload-sarif is enabled but no github-token was provided — skipping upload.');
    return;
  }
  try {
    const { context, getOctokit } = await import('@actions/github');
    const compressed = zlib.gzipSync(fs.readFileSync(sarifPath)).toString('base64');
    const octokit = getOctokit(inputs.githubToken);
    await octokit.rest.codeScanning.uploadSarif({
      owner: context.repo.owner,
      repo: context.repo.repo,
      commit_sha: context.sha,
      ref: context.ref,
      sarif: compressed,
      tool_name: 'chainwatch',
    });
    core.info('SARIF uploaded to GitHub code scanning.');
  } catch (e) {
    // Upload failures (missing permissions, SARIF validation) shouldn't fail the run.
    core.warning(`SARIF upload failed: ${(e as Error).message}`);
    core.warning('Ensure the workflow grants `security-events: write` permission.');
  }
}

run();
