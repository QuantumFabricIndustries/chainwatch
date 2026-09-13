/**
 * `chainwatch sync` — push local findings to the ChainWatch Cloud API.
 *
 * Usage: chainwatch sync [options]
 *
 * Options:
 *   --api-key <key>    ChainWatch API key (or set CHAINWATCH_API_KEY env var)
 *   --repo <name>      Repo name to tag findings with (default: git remote origin)
 *   --since <date>     Only sync findings since this date
 *   --dry-run          Show what would be synced without sending
 */

import type { Command } from 'commander';
import { syncFindings, detectRepoName, closeNetworkConnections } from '../../sync/client.js';
import type { Finding } from '../../scan/finding.js';

export function registerSync(program: Command): void {
  program
    .command('sync')
    .description('Push local findings to the ChainWatch Cloud API')
    .option('--api-key <key>', 'ChainWatch API key (or set CHAINWATCH_API_KEY env var)')
    .option('--repo <name>', 'Repo name (default: auto-detect from git remote)')
    .option('--since <date>', 'Only sync findings since this date')
    .option('--dry-run', 'Show what would be synced without sending')
    .action(async (opts: SyncCliOpts) => {
      await runSync(opts);
    });
}

interface SyncCliOpts {
  apiKey?: string;
  repo?: string;
  since?: string;
  dryRun?: boolean;
}

async function runSync(opts: SyncCliOpts): Promise<void> {
  const apiKey = opts.apiKey ?? process.env['CHAINWATCH_API_KEY'];
  if (!apiKey) {
    console.error('No API key found. Set CHAINWATCH_API_KEY env var or use --api-key.');
    console.error('Get an API key at https://chainwatch.dev/signup');
    process.exit(1);
  }

  const repo = opts.repo ?? (await detectRepoName());
  if (!repo) {
    console.error('Could not detect repo name from git remote. Use --repo to specify.');
    process.exit(1);
  }

  // In a full implementation, this would read from a local SQLite event log
  // (Phase 2+ feature). For now, sync reads from the last scan results file
  // if available, or the user provides findings via stdin.
  console.log(`ChainWatch sync: ${repo}`);
  console.log('');

  // Check for a local findings file from a previous scan.
  const { existsSync, readFileSync } = await import('node:fs');
  const { resolve } = await import('node:path');
  const findingsFile = resolve('.chainwatch/last-scan.json');

  if (!existsSync(findingsFile)) {
    console.error('No local findings to sync. Run `chainwatch scan` first.');
    console.error(`Expected: ${findingsFile}`);
    process.exit(1);
  }

  const content = readFileSync(findingsFile, 'utf8');
  const data = JSON.parse(content) as { findings: Finding[]; run_id: string; timestamp: string };

  const findings = data.findings;
  if (opts.since) {
    const sinceDate = new Date(opts.since);
    if (Number.isNaN(sinceDate.getTime())) {
      console.error(`Invalid --since date "${opts.since}".`);
      process.exit(1);
    }
    // Findings don't carry individual timestamps — the scan as a whole does.
    // If the scan predates --since, there's nothing to send.
    if (new Date(data.timestamp) < sinceDate) {
      console.log(`Last scan (${data.timestamp}) predates --since ${opts.since}. Nothing to sync.`);
      process.exit(0);
    }
  }

  if (findings.length === 0) {
    console.log('No findings to sync.');
    process.exit(0);
  }

  console.log(`  Syncing ${findings.length} findings...`);

  const result = await syncFindings(findings, data.run_id, {
    apiKey,
    repo,
    dryRun: opts.dryRun,
  });

  if (result.skipped) {
    console.log('  Skipped (no API key configured).');
  } else if (result.error) {
    console.error(`  Failed: ${result.error}`);
    await closeNetworkConnections();
    process.exit(1);
  } else {
    console.log(`  ✓ Synced ${result.ingested} findings to cloud.`);
  }
  await closeNetworkConnections();
}
