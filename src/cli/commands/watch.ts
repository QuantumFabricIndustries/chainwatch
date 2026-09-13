/**
 * `chainwatch watch` — run a command under the live runtime interceptor.
 *
 * Spawns the user's command as a child process with the ChainWatch preload
 * injected via NODE_OPTIONS="--import <preload>". Events stream back via a
 * JSONL log file that the parent tails in real time.
 *
 * With --drift, uses the recorder preload instead and compares behavior
 * to a recorded baseline after the run.
 */

import type { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { ChildProcess } from 'node:child_process';
import { spawnWatched } from '../../spawn-watched.js';
import type { ChainWatchEvent } from '../../events.js';
import { formatEvent } from '../../reporter/index.js';
import { readBaseline, compactBaseline } from '../../baseline/store.js';
import { diffBaseline, type DriftResult } from '../../baseline/differ.js';
import { formatDriftReport } from '../../baseline/summarizer.js';
import type { BaselineEvent } from '../../baseline/types.js';

const __filename_esm = fileURLToPath(import.meta.url);
const __dirname_esm = path.dirname(__filename_esm);

const VALID_BLOCK_LEVELS = ['low', 'medium', 'high', 'critical'] as const;

export function registerWatch(program: Command): void {
  program
    .command('watch [args...]')
    .description('Run a command under live ChainWatch monitoring')
    .option('--block', 'Block on HIGH+ (default: warn only, block on critical)')
    .option('--block-on <lvl>', 'Block threshold: low|medium|high|critical', 'critical')
    .option('--trust <pkgs>', 'Comma-separated package names to never block')
    .option('--allow <hosts>', 'Comma-separated extra allowlist hosts')
    .option('-o, --output <fmt>', 'Output format: pretty | json', 'pretty')
    .option('--log <file>', 'Append events to a JSONL log file')
    .option('--drift', 'Enable drift detection (requires baseline)')
    .option('--baseline <file>', 'Baseline file to compare against', '.chainwatch/baseline.jsonl')
    .option('--drift-threshold <n>', 'Drift score to trigger alert (0–100)', '40')
    .option('--block-on-drift', 'Block the process if drift score exceeds threshold')
    .option('--sync', 'Push events to ChainWatch Cloud after run')
    .allowUnknownOption(true)
    .action(async (args: string[], opts: WatchCliOpts) => {
      const cmdArgs = extractCommandArgs();
      if (cmdArgs.length === 0) {
        console.error('Usage: chainwatch watch -- <command>');
        console.error('Example: chainwatch watch -- node server.js');
        process.exit(1);
      }
      if (opts.drift) {
        await runDriftWatch(cmdArgs, opts);
      } else {
        await runWatch(cmdArgs, opts);
      }
    });
}

interface WatchCliOpts {
  block?: boolean;
  blockOn?: string;
  trust?: string;
  allow?: string;
  output?: string;
  log?: string;
  drift?: boolean;
  baseline?: string;
  driftThreshold?: string;
  blockOnDrift?: boolean;
  sync?: boolean;
}

function extractCommandArgs(): string[] {
  const idx = process.argv.indexOf('--');
  if (idx === -1) return [];
  return process.argv.slice(idx + 1);
}

/** Build the child-process env: preload + policy wiring. */
function childEnv(opts: WatchCliOpts, preloadUrl: string, extra: Record<string, string>): NodeJS.ProcessEnv {
  // --block means "block on high+"; --block-on overrides it entirely.
  const blockOn = opts.block ? 'high' : opts.blockOn;
  if (blockOn && !VALID_BLOCK_LEVELS.includes(blockOn as typeof VALID_BLOCK_LEVELS[number])) {
    console.error(`Invalid --block-on level "${blockOn}". Must be: ${VALID_BLOCK_LEVELS.join(', ')}`);
    process.exit(1);
  }
  return {
    ...process.env,
    NODE_OPTIONS: `${process.env['NODE_OPTIONS'] ?? ''} --import ${preloadUrl}`.trim(),
    CHAINWATCH_PRELOAD_URL: preloadUrl,
    ...(blockOn ? { CHAINWATCH_BLOCK_ON: blockOn } : {}),
    ...(opts.trust ? { CHAINWATCH_TRUSTED: opts.trust } : {}),
    ...(opts.allow ? { CHAINWATCH_ALLOW_HOSTS: opts.allow } : {}),
    ...extra,
  };
}

/** Normalize a child exit: signal kills become their conventional 128+n code. */
function exitCodeOf(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) return code;
  const signo: Record<string, number> = { SIGINT: 2, SIGTERM: 15, SIGKILL: 9, SIGHUP: 1, SIGPIPE: 13 };
  return 128 + (signal ? (signo[signal] ?? 0) : 0) || 1;
}

/**
 * Incremental JSONL tail reader. Reads only complete lines — a partial line
 * (in-flight write or a multi-byte char split) stays buffered for next poll.
 */
class JsonlTail {
  private offset = 0;
  private pending = '';
  constructor(private readonly file: string) {}

  /** Returns newly completed parsed lines since last call. */
  poll<T>(): T[] {
    let buf: Buffer;
    try {
      const fd = fs.openSync(this.file, 'r');
      try {
        const stat = fs.fstatSync(fd);
        if (stat.size <= this.offset) return [];
        buf = Buffer.alloc(stat.size - this.offset);
        fs.readSync(fd, buf, 0, buf.length, this.offset);
        this.offset = stat.size;
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return []; // file doesn't exist yet / vanished
    }

    this.pending += buf.toString('utf8');
    const lastNl = this.pending.lastIndexOf('\n');
    if (lastNl === -1) return [];
    const complete = this.pending.slice(0, lastNl);
    this.pending = this.pending.slice(lastNl + 1);

    const out: T[] = [];
    for (const line of complete.split('\n')) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line) as T);
      } catch { /* corrupt line — skip */ }
    }
    return out;
  }

  /** Force-flush any remaining partial line (end of run). */
  flush<T>(): T[] {
    const rest = this.pending.trim();
    this.pending = '';
    if (!rest) return [];
    try {
      return [JSON.parse(rest) as T];
    } catch {
      return [];
    }
  }
}

// ─── Standard watch (Phase 1 interceptor) ───────────────────────────────────

async function runWatch(cmdArgs: string[], opts: WatchCliOpts): Promise<void> {
  const eventLogPath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'chainwatch-watch-')),
    'events.jsonl',
  );

  const preloadPath = resolvePreload('preload.js');
  const preloadUrl = pathToFileURL(preloadPath).href;
  const env = childEnv(opts, preloadUrl, { CHAINWATCH_EVENT_LOG: eventLogPath });

  const child: ChildProcess = spawnWatched(cmdArgs, { env, stdio: 'inherit' });

  console.log(`ChainWatch watching: ${cmdArgs.join(' ')}`);
  console.log(`Policy: default (warn on high, block on ${opts.block ? 'high' : opts.blockOn ?? 'critical'})\n`);

  const events: ChainWatchEvent[] = [];
  const tail = new JsonlTail(eventLogPath);

  const tailInterval = setInterval(() => {
    for (const event of tail.poll<ChainWatchEvent>()) {
      events.push(event);
      printWatchEvent(event, opts);
    }
  }, 100);

  const exitCode = await new Promise<number>((resolve) => {
    child.on('exit', (code, signal) => resolve(exitCodeOf(code, signal)));
    child.on('error', (err) => {
      console.error(`chainwatch: failed to spawn command: ${err.message}`);
      resolve(1);
    });
  });

  clearInterval(tailInterval);
  for (const event of [...tail.poll<ChainWatchEvent>(), ...tail.flush<ChainWatchEvent>()]) {
    events.push(event);
    printWatchEvent(event, opts);
  }

  console.log('\n  ' + '─'.repeat(50));
  const blocked = events.filter((e) => e.action === 'block').length;
  const flagged = events.filter((e) => e.action === 'flag').length;
  console.log(`  Watch complete. ${events.length} events — ${blocked} blocked, ${flagged} flagged`);
  console.log(`  Command exit code: ${exitCode}`);

  if (opts.log) {
    try { for (const e of events) fs.appendFileSync(opts.log, JSON.stringify(e) + '\n'); } catch { /* */ }
  }

  // Sync to cloud if --sync flag is set.
  if (opts.sync && events.length > 0) {
    const { syncFindings, detectRepoName } = await import('../../sync/client.js');
    const repo = await detectRepoName() ?? undefined;
    // Convert ChainWatchEvents to Findings for sync (schema requires strings).
    const findings = events.map((e) => ({
      rule: e.signal,
      severity: e.severity,
      package: e.package,
      description: describeEvent(e),
      chain_score: (e.detail['chainScore'] as number) ?? e.score,
    }));
    const runId = `watch-${Date.now()}`;
    const syncResult = await syncFindings(findings as any, runId, { repo });
    if (!syncResult.skipped && !syncResult.error) {
      console.log(`  Synced ${syncResult.ingested} events to cloud.`);
    } else if (syncResult.error) {
      console.error(`  Sync failed: ${syncResult.error}`);
    }
    const { closeNetworkConnections } = await import('../../sync/client.js');
    await closeNetworkConnections();
  }

  try { fs.rmSync(path.dirname(eventLogPath), { recursive: true, force: true }); } catch { /* */ }
  process.exit(exitCode);
}

/** Human-readable one-liner for an event's detail object (for sync). */
function describeEvent(e: ChainWatchEvent): string {
  const parts = Object.entries(e.detail)
    .filter(([k]) => k !== 'chainScore' && k !== 'occurrences')
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`);
  return `${e.signal}${parts.length ? ': ' + parts.join(' ') : ''}`;
}

function printWatchEvent(e: ChainWatchEvent, opts: WatchCliOpts): void {
  if (opts.output === 'json') {
    console.log(JSON.stringify(e));
  } else {
    console.log(formatEvent(e));
  }
}

// ─── Drift watch (Phase 3) ──────────────────────────────────────────────────

async function runDriftWatch(cmdArgs: string[], opts: WatchCliOpts): Promise<void> {
  const baselinePath = path.resolve(opts.baseline ?? '.chainwatch/baseline.jsonl');
  const driftThreshold = parseInt(opts.driftThreshold ?? '40', 10);
  if (!Number.isFinite(driftThreshold) || driftThreshold < 0 || driftThreshold > 100) {
    console.error(`Invalid --drift-threshold "${opts.driftThreshold}". Must be 0–100.`);
    process.exit(1);
  }

  // Load baseline.
  const baselineEvents = readBaseline(baselinePath);
  if (baselineEvents.length === 0) {
    console.error(`No baseline found at ${baselinePath}`);
    console.error('Run `chainwatch baseline record -- <cmd>` to create one.');
    process.exit(1);
  }
  const baseline = compactBaseline(baselineEvents);

  const recorderLogPath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'chainwatch-drift-')),
    'recorder.jsonl',
  );

  const preloadPath = resolvePreload('recorder-preload.js');
  const preloadUrl = pathToFileURL(preloadPath).href;
  const env = childEnv(opts, preloadUrl, { CHAINWATCH_RECORDER_LOG: recorderLogPath });

  const child: ChildProcess = spawnWatched(cmdArgs, { env, stdio: 'inherit' });

  console.log(`ChainWatch watching: ${cmdArgs.join(' ')} [drift detection ON]`);
  console.log(`Baseline: ${baselinePath} (${baseline.events.size} events, ${baseline.runCount} runs)\n`);

  const tail = new JsonlTail(recorderLogPath);
  const liveEvents: BaselineEvent[] = [];

  let killed = false;
  if (opts.blockOnDrift) {
    // Check for drift periodically and kill if threshold exceeded.
    const checkInterval = setInterval(() => {
      liveEvents.push(...tail.poll<BaselineEvent>());
      const results = diffBaseline(liveEvents, baseline);
      const highDrift = results.filter((r) => r.driftScore >= driftThreshold);
      if (highDrift.length > 0 && !killed) {
        killed = true;
        console.log('\n  🛑 Drift threshold exceeded — killing process\n');
        child.kill('SIGKILL');
      }
    }, 500);
    child.on('exit', () => clearInterval(checkInterval));
  }

  const exitCode = await new Promise<number>((resolve) => {
    child.on('exit', (code, signal) => resolve(exitCodeOf(code, signal)));
    child.on('error', (err) => {
      console.error(`chainwatch: failed to spawn command: ${err.message}`);
      resolve(1);
    });
  });

  // Give the child's process.on('exit') handler time to flush remaining events
  // to the recorder log file before the final read.
  await new Promise((resolve) => setTimeout(resolve, 300));

  // Read all recorded events and compute drift.
  const recordedEvents: BaselineEvent[] = [...liveEvents, ...tail.poll<BaselineEvent>(), ...tail.flush<BaselineEvent>()];

  const results = diffBaseline(recordedEvents, baseline);
  const useColor = process.stdout.isTTY;
  const aboveThreshold = results.filter((r) => r.driftScore >= driftThreshold);

  console.log('\n  ' + '─'.repeat(50));
  console.log(formatDriftReport(results, baseline, { useColor }));

  if (opts.log) {
    try { for (const r of results) fs.appendFileSync(opts.log, JSON.stringify(r) + '\n'); } catch { /* */ }
  }

  try { fs.rmSync(path.dirname(recorderLogPath), { recursive: true, force: true }); } catch { /* */ }

  const finalExit = (killed || aboveThreshold.length > 0) ? 1 : exitCode;
  process.exit(finalExit);
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

function resolvePreload(filename: string): string {
  const candidates = [
    path.resolve(__dirname_esm, `../${filename}`),
    path.resolve(__dirname_esm, `../../${filename}`),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[0]!;
}
