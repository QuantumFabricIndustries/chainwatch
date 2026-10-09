/**
 * Pretty reporter — human-readable scan output for terminals.
 */

import type { Finding, Severity } from '../scan/finding.js';
import { meetsSeverity } from '../scan/finding.js';

const SEV_COLOR: Record<Severity, string> = {
  critical: '\x1b[41;37;1m',
  high: '\x1b[31;1m',
  medium: '\x1b[33;1m',
  low: '\x1b[37m',
};
const RESET = '\x1b[0m';

export interface PrettyOptions {
  useColor: boolean;
  quiet: boolean;
  /** Scanned directory shown in the header (default ./node_modules). */
  scanDir?: string;
}

export function formatPretty(
  findings: Finding[],
  pkgCount: number,
  scanMs: number,
  opts: PrettyOptions,
): string {
  const c = (s: Severity) => (opts.useColor ? SEV_COLOR[s] : '');
  const r = () => (opts.useColor ? RESET : '');
  const lines: string[] = [];

  if (!opts.quiet) {
    lines.push(`ChainWatch scan — ${opts.scanDir ?? './node_modules'} (${pkgCount} packages)`);
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push('  No findings. Clean scan.');
    lines.push('');
    lines.push('  ' + '─'.repeat(50));
    lines.push(`  Scanned: ${pkgCount} packages`);
    lines.push(`  Findings: 0`);
    lines.push(`  Scan time: ${(scanMs / 1000).toFixed(1)}s`);
    return lines.join('\n');
  }

  if (findings.some((f) => f.rule === 'hostage_token')) {
    lines.push(`  ${c('critical')}!! STOP: do not revoke GitHub tokens yet.${r()}`);
    lines.push('     A token-stealing worm here may wipe your home directory when its token is revoked.');
    lines.push('     Run `chainwatch hostage-check` and remove the monitor first.');
    lines.push('');
  }

  for (const f of findings) {
    lines.push(`  ${c(f.severity)}${f.severity.toUpperCase().padEnd(8)}${r()} ${f.rule.padEnd(20)} ${f.package}`);
    lines.push(`          ${f.description}`);
    if (f.file) lines.push(`          File: ${f.file}`);
    if (f.evidence) lines.push(`          Evidence: ${f.evidence}`);
    lines.push('');
  }

  const counts: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity]++;

  lines.push('  ' + '─'.repeat(50));
  lines.push(`  Scanned: ${pkgCount} packages`);
  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical} critical`);
  if (counts.high) parts.push(`${counts.high} high`);
  if (counts.medium) parts.push(`${counts.medium} medium`);
  if (counts.low) parts.push(`${counts.low} low`);
  lines.push(`  Findings: ${parts.join(', ')}`);
  lines.push(`  Scan time: ${(scanMs / 1000).toFixed(1)}s`);

  return lines.join('\n');
}

/** Exit code logic: 1 if any finding meets failOn severity, else 0. */
export function exitCodeFor(findings: Finding[], failOn: Severity): number {
  return findings.some((f) => meetsSeverity(f.severity, failOn)) ? 1 : 0;
}
