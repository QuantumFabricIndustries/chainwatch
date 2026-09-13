/**
 * JSON reporter — machine-parseable scan output.
 */

import type { Finding } from '../scan/finding.js';
import { CW_VERSION } from '../version.js';

export interface JsonReport {
  scanner: 'chainwatch';
  version: string;
  timestamp: string;
  packageCount: number;
  scanMs: number;
  findings: Finding[];
}

export function formatJson(
  findings: Finding[],
  pkgCount: number,
  scanMs: number,
): string {
  const report: JsonReport = {
    scanner: 'chainwatch',
    version: CW_VERSION,
    timestamp: new Date().toISOString(),
    packageCount: pkgCount,
    scanMs,
    findings,
  };
  return JSON.stringify(report, null, 2);
}
