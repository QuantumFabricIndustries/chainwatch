/**
 * qf-findings/1 reporter — shared QFI findings contract.
 *
 * Schema: `qf-findings/schema.json` at the ecosystem root.
 * Fingerprints are `sha256(check_id|package|file|description)[:16]` — stable
 * across runs and machines (no timestamps, absolute paths, or random ids).
 */

import { createHash } from 'node:crypto';
import type { Finding, Severity } from '../scan/finding.js';
import { getRuleId } from './sarif.js';
import { CW_VERSION } from '../version.js';

const QF_SEVERITY: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

interface QfFinding {
  fingerprint: string;
  severity: string;
  check_id: string;
  title: string;
  description: string;
  subject?: string;
  detail?: string;
}

export interface QfReport {
  schema: 'qf-findings/1';
  tool: { name: string; version: string };
  scan_time: string;
  score: { value: number; grade: string };
  findings: QfFinding[];
}

function fingerprint(checkId: string, pkg: string, file: string, desc: string): string {
  return createHash('sha256')
    .update(`${checkId}|${pkg}|${file}|${desc}`)
    .digest('hex')
    .slice(0, 16);
}

function severityScore(findings: Finding[]): { value: number; grade: string } {
  if (findings.length === 0) return { value: 0, grade: 'CLEAN' };
  const worst = Math.max(
    ...findings.map((f) => ({ low: 10, medium: 40, high: 70, critical: 95 })[f.severity]),
  );
  const grade = worst >= 95 ? 'CRITICAL' : worst >= 70 ? 'HIGH' : worst >= 40 ? 'MEDIUM' : 'LOW';
  return { value: worst, grade };
}

export function generateQfObject(findings: Finding[], toolVersion = CW_VERSION): QfReport {
  return {
    schema: 'qf-findings/1',
    tool: { name: 'chainwatch', version: toolVersion },
    scan_time: new Date().toISOString(),
    score: severityScore(findings),
    findings: findings.map((f) => {
      const checkId = /^[A-Z]{2,6}[0-9]{3}$/.test(getRuleId(f.rule))
        ? getRuleId(f.rule)
        : 'CW999';
      const out: QfFinding = {
        fingerprint: fingerprint(checkId, f.package, f.file ?? '', f.description),
        severity: QF_SEVERITY[f.severity],
        check_id: checkId,
        title: f.rule,
        description: f.description,
        subject: f.package,
      };
      const detailParts = [f.file, f.evidence].filter(Boolean);
      if (detailParts.length) out.detail = detailParts.join(' — ');
      return out;
    }),
  };
}

export function formatQf(findings: Finding[], toolVersion = CW_VERSION): string {
  return JSON.stringify(generateQfObject(findings, toolVersion), null, 2);
}
