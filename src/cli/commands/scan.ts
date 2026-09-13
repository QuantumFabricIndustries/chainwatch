/**
 * `chainwatch scan` — static analysis of node_modules.
 */

import type { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { scan, type ScanOptions } from '../../scan/scanner.js';
import type { Severity } from '../../scan/finding.js';
import { formatPretty, formatJson, formatSarif, exitCodeFor } from '../../reporter/index.js';
import { syncFindings, detectRepoName, closeNetworkConnections } from '../../sync/client.js';

export function registerScan(program: Command): void {
  program
    .command('scan [dir]')
    .description('Statically scan node_modules for supply-chain risks')
    .option('-o, --output <fmt>', 'Output format: pretty | json | sarif', 'pretty')
    .option('-s, --severity <lvl>', 'Minimum severity: low|medium|high|critical', 'medium')
    .option('--fail-on <lvl>', 'Exit 1 if any finding >= this severity', 'high')
    .option('--sarif-output <file>', 'Write SARIF output to this file (in addition to stdout)')
    .option('--sync', 'Push findings to ChainWatch Cloud after scan')
    .option('--no-color', 'Disable color output')
    .option('-q, --quiet', 'Only print findings, no progress')
    .action(async (dir: string | undefined, opts: ScanCliOpts) => {
      const target = path.resolve(dir ?? './node_modules');
      const minSev = (opts.severity ?? 'medium') as Severity;
      const failOn = (opts.failOn ?? 'high') as Severity;

      const result = await scan(target, {
        minSeverity: minSev,
      });

      const useColor = opts.color !== false && process.stdout.isTTY;

      let output: string;
      switch (opts.output) {
        case 'json':
          output = formatJson(result.findings, result.packageCount, result.scanMs);
          break;
        case 'sarif':
          output = formatSarif(result.findings);
          break;
        default:
          output = formatPretty(result.findings, result.packageCount, result.scanMs, {
            useColor,
            quiet: opts.quiet ?? false,
            scanDir: dir ?? './node_modules',
          });
      }

      console.log(output);

      // Write SARIF to file if requested (for GitHub Action / CI integration).
      if (opts.sarifOutput) {
        const sarifPath = path.resolve(opts.sarifOutput);
        const sarifContent = formatSarif(result.findings);
        try {
          fs.writeFileSync(sarifPath, sarifContent, 'utf8');
          if (!opts.quiet) {
            console.error(`SARIF written to ${sarifPath}`);
          }
        } catch (e) {
          console.error(`Failed to write SARIF to ${sarifPath}: ${(e as Error).message}`);
        }
      }

      // Save last scan results for `chainwatch sync` to pick up.
      if (result.findings.length > 0 || opts.sync) {
        const scanDir = path.resolve('.chainwatch');
        if (!fs.existsSync(scanDir)) fs.mkdirSync(scanDir, { recursive: true });
        const runId = `scan-${Date.now()}`;
        fs.writeFileSync(
          path.join(scanDir, 'last-scan.json'),
          JSON.stringify({ findings: result.findings, run_id: runId, timestamp: new Date().toISOString() }),
          'utf8',
        );
      }

      // Sync to cloud if --sync flag is set.
      if (opts.sync) {
        const repo = await detectRepoName() ?? undefined;
        const runId = `scan-${Date.now()}`;
        const syncResult = await syncFindings(result.findings, runId, { repo });
        if (!syncResult.skipped && !syncResult.error) {
          console.error(`  Synced ${syncResult.ingested} findings to cloud.`);
        } else if (syncResult.error) {
          console.error(`  Sync failed: ${syncResult.error}`);
        }
        // Silently skip if no API key (skipped=true).
      }

      const code = exitCodeFor(result.findings, failOn);
      if (opts.sync) await closeNetworkConnections();
      process.exit(code);
    });
}

interface ScanCliOpts {
  output?: string;
  severity?: string;
  failOn?: string;
  sarifOutput?: string;
  sync?: boolean;
  color?: boolean;
  quiet?: boolean;
}
