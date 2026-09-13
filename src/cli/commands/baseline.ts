/**
 * `chainwatch baseline` — record and inspect behavioral baselines.
 *
 * Subcommands:
 *   record  — run a command and record its behavior as the baseline
 *   show    — display the recorded baseline
 *   clear   — delete the baseline file
 */

import type { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { ChildProcess } from 'node:child_process';
import { spawnWatched } from '../../spawn-watched.js';

import { readBaseline, compactBaseline, writeBaseline } from '../../baseline/store.js';
import { formatBaselineSummary } from '../../baseline/summarizer.js';

const __filename_esm = fileURLToPath(import.meta.url);
const __dirname_esm = path.dirname(__filename_esm);

const DEFAULT_BASELINE = '.chainwatch/baseline.jsonl';

export function registerBaseline(program: Command): void {
  const baseline = program.command('baseline').description('Record and inspect behavioral baselines');

  baseline
    .command('record [args...]')
    .description('Run a command and record its behavior as the baseline')
    .option('--baseline <file>', 'Baseline file path', DEFAULT_BASELINE)
    .option('--merge', 'Merge into existing baseline (default: overwrite)')
    .option('--runs <n>', 'Record N runs and merge', '1')
    .option('--tag <label>', 'Tag this baseline run')
    .option('--sync', 'Upload baseline to ChainWatch Cloud after recording')
    .allowUnknownOption(true)
    .action(async (args: string[], opts: BaselineRecordOpts) => {
      const cmdArgs = extractCommandArgs();
      if (cmdArgs.length === 0) {
        console.error('Usage: chainwatch baseline record -- <command>');
        process.exit(1);
      }
      await runRecord(cmdArgs, opts);
    });

  baseline
    .command('pull')
    .description('Download the team baseline from ChainWatch Cloud')
    .option('--baseline <file>', 'Baseline file path', DEFAULT_BASELINE)
    .option('--lockfile <file>', 'Lockfile to hash for lookup', 'package-lock.json')
    .option('--repo <name>', 'Repo name (default: auto-detect from git remote)')
    .action(async (opts: BaselinePullOpts) => {
      await runPull(opts);
    });

  baseline
    .command('show')
    .description('Display the recorded baseline')
    .option('--baseline <file>', 'Baseline file path', DEFAULT_BASELINE)
    .option('--pkg <name>', 'Filter to a specific package')
    .option('--signal <sig>', 'Filter to a specific signal type')
    .option('--json', 'Output raw JSON')
    .action((opts: BaselineShowOpts) => {
      runShow(opts);
    });

  baseline
    .command('clear')
    .description('Delete the baseline file')
    .option('--baseline <file>', 'Baseline file path', DEFAULT_BASELINE)
    .action((opts: BaselineClearOpts) => {
      const file = path.resolve(opts.baseline ?? DEFAULT_BASELINE);
      try {
        fs.rmSync(file, { force: true });
        console.log(`Cleared: ${file}`);
      } catch {
        console.error(`Failed to clear: ${file}`);
      }
    });
}

interface BaselineRecordOpts {
  baseline?: string;
  merge?: boolean;
  runs?: string;
  tag?: string;
  sync?: boolean;
  repo?: string;
}

interface BaselineShowOpts {
  baseline?: string;
  pkg?: string;
  signal?: string;
  json?: boolean;
}

interface BaselineClearOpts {
  baseline?: string;
}

interface BaselinePullOpts {
  baseline?: string;
  lockfile?: string;
  repo?: string;
}

function extractCommandArgs(): string[] {
  const idx = process.argv.indexOf('--');
  if (idx === -1) return [];
  return process.argv.slice(idx + 1);
}

async function runRecord(cmdArgs: string[], opts: BaselineRecordOpts): Promise<void> {
  const baselinePath = path.resolve(opts.baseline ?? DEFAULT_BASELINE);
  const runs = parseInt(opts.runs ?? '1', 10);
  if (!Number.isFinite(runs) || runs < 1) {
    console.error(`Invalid --runs value "${opts.runs}". Must be a positive integer.`);
    process.exit(1);
  }
  const tag = opts.tag;

  // Resolve the recorder preload path.
  const candidates = [
    path.resolve(__dirname_esm, '../recorder-preload.js'),
    path.resolve(__dirname_esm, '../../recorder-preload.js'),
  ];
  const preloadPath = candidates.find((p) => fs.existsSync(p)) ?? candidates[0]!;
  const preloadUrl = pathToFileURL(preloadPath).href;

  // If not merging, clear the file first.
  if (!opts.merge && fs.existsSync(baselinePath)) {
    fs.rmSync(baselinePath, { force: true });
  }

  // Ensure the baseline directory exists (the child process also does this,
  // but we do it here too to avoid any race).
  const baselineDir = path.dirname(baselinePath);
  if (!fs.existsSync(baselineDir)) {
    fs.mkdirSync(baselineDir, { recursive: true });
  }

  for (let run = 1; run <= runs; run++) {
    console.log(`ChainWatch baseline recording: ${cmdArgs.join(' ')} (run ${run} of ${runs})`);
    console.log('');

    const env = {
      ...process.env,
      NODE_OPTIONS: `${process.env['NODE_OPTIONS'] ?? ''} --import ${preloadUrl}`.trim(),
      CHAINWATCH_PRELOAD_URL: preloadUrl,
      CHAINWATCH_BASELINE_FILE: baselinePath,
      ...(tag ? { CHAINWATCH_BASELINE_TAG: tag } : {}),
    };

    const child: ChildProcess = spawnWatched(cmdArgs, { env, stdio: 'inherit' });

    const exitCode = await new Promise<number>((resolve) => {
      child.on('exit', (code, signal) => {
        if (code !== null) return resolve(code);
        const signo: Record<string, number> = { SIGINT: 2, SIGTERM: 15, SIGKILL: 9 };
        resolve(signal ? 128 + (signo[signal] ?? 0) : 1);
      });
      child.on('error', (err) => {
        console.error(`chainwatch: failed to spawn command: ${err.message}`);
        resolve(1);
      });
    });

    if (exitCode !== 0) {
      console.error(`\n  Command exited with code ${exitCode} on run ${run}. Baseline may be incomplete.`);
      if (run < runs) console.error('  Continuing with remaining runs...');
    }
  }

  // Read and summarize the recorded baseline.
  const events = readBaseline(baselinePath);
  const compacted = compactBaseline(events);

  console.log('');
  console.log(`  ✓ Baseline recorded: ${baselinePath}`);
  console.log(`    Packages observed: ${new Set(events.map((e) => e.pkg)).size}`);
  console.log(`    Events recorded:   ${events.length}`);
  console.log(`    Unique signals:    ${compacted.events.size}`);
  console.log('');
  console.log('  Run `chainwatch baseline show` to inspect it.');
  console.log('  Run `chainwatch watch --drift -- <cmd>` to detect deviations.');

  // Sync to cloud if --sync flag is set.
  if (opts.sync) {
    const { syncBaseline, hashFile, detectRepoName } = await import('../../sync/client.js');
    const lockfilePath = path.resolve('package-lock.json');
    let lockfileHash = 'unknown';
    try {
      lockfileHash = await hashFile(lockfilePath);
    } catch { /* no lockfile */ }
    const repo = opts.repo ?? (await detectRepoName()) ?? undefined;
    const syncResult = await syncBaseline(baselinePath, lockfileHash, { repo });
    if (!syncResult.skipped && !syncResult.error) {
      console.log('  ✓ Baseline uploaded to cloud.');
    } else if (syncResult.error) {
      console.error(`  Sync failed: ${syncResult.error}`);
    }
  }
}

async function runPull(opts: BaselinePullOpts): Promise<void> {
  const baselinePath = path.resolve(opts.baseline ?? DEFAULT_BASELINE);
  const lockfilePath = path.resolve(opts.lockfile ?? 'package-lock.json');

  const { pullBaseline, hashFile, detectRepoName } = await import('../../sync/client.js');

  let lockfileHash: string;
  try {
    lockfileHash = await hashFile(lockfilePath);
  } catch {
    console.error(`Cannot read lockfile: ${lockfilePath}`);
    process.exit(1);
  }

  const repo = opts.repo ?? (await detectRepoName());
  if (!repo) {
    console.error('Could not detect repo name. Use --repo to specify.');
    process.exit(1);
  }

  console.log(`Pulling team baseline for ${repo} (lockfile: ${lockfileHash.slice(0, 12)}...)`);
  const result = await pullBaseline(lockfileHash, baselinePath, { repo });
  const { closeNetworkConnections } = await import('../../sync/client.js');
  await closeNetworkConnections();
  if (result.skipped) {
    console.error('No API key configured. Set CHAINWATCH_API_KEY env var.');
    process.exit(1);
  } else if (result.error) {
    console.error(`Failed: ${result.error}`);
    process.exit(1);
  } else {
    console.log(`  ✓ Baseline pulled to ${baselinePath}`);
  }
}

function runShow(opts: BaselineShowOpts): void {
  const baselinePath = path.resolve(opts.baseline ?? DEFAULT_BASELINE);
  const events = readBaseline(baselinePath);

  if (events.length === 0) {
    console.log(`No baseline found at ${baselinePath}`);
    console.log('Run `chainwatch baseline record -- <cmd>` to create one.');
    return;
  }

  let filtered = events;
  if (opts.pkg) {
    filtered = filtered.filter((e) => e.pkg.includes(opts.pkg!));
  }
  if (opts.signal) {
    filtered = filtered.filter((e) => e.signal === opts.signal);
  }

  if (opts.json) {
    console.log(JSON.stringify(filtered, null, 2));
    return;
  }

  const compacted = compactBaseline(filtered);
  const useColor = process.stdout.isTTY;
  console.log(formatBaselineSummary(compacted, baselinePath, { useColor }));
}
