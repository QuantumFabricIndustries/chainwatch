import { describe, it, expect } from 'vitest';
import { generateQfObject, formatQf } from '../../src/reporter/qf.js';
import type { Finding } from '../../src/scan/finding.js';

function makeFinding(rule: string, severity: Finding['severity'], pkg = 'test-pkg@1.0.0', file?: string): Finding {
  return {
    rule,
    severity,
    package: pkg,
    description: `Test finding for ${rule}`,
    ...(file ? { file } : {}),
  };
}

describe('qf-findings/1 reporter', () => {
  it('emits the contract root shape', () => {
    const qf = generateQfObject([makeFinding('postinstall_network', 'high')]);
    expect(qf.schema).toBe('qf-findings/1');
    expect(qf.tool.name).toBe('chainwatch');
    expect(qf.tool.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(qf.scan_time).toBeTruthy();
    expect(qf.score.value).toBeGreaterThanOrEqual(0);
    expect(qf.score.value).toBeLessThanOrEqual(100);
    expect(qf.findings).toHaveLength(1);
  });

  it('reuses CWxxx rule IDs as check_ids', () => {
    const qf = generateQfObject([makeFinding('postinstall_network', 'high')]);
    expect(qf.findings[0]!.check_id).toBe('CW001');
  });

  it('falls back to CW999 for unknown rules', () => {
    const qf = generateQfObject([makeFinding('custom_rule', 'low')]);
    expect(qf.findings[0]!.check_id).toBe('CW999');
    expect(qf.findings[0]!.check_id).toMatch(/^[A-Z]{2,6}[0-9]{3}$/);
  });

  it('maps severity upward correctly', () => {
    const qf = generateQfObject([
      makeFinding('postinstall_network', 'critical'),
      makeFinding('postinstall_shell', 'low'),
      makeFinding('credential_file_access', 'medium'),
    ]);
    expect(qf.findings[0]!.severity).toBe('CRITICAL');
    expect(qf.findings[1]!.severity).toBe('LOW');
    expect(qf.findings[2]!.severity).toBe('MEDIUM');
    expect(qf.score.value).toBe(95); // worst-severity scoring
    expect(qf.score.grade).toBe('CRITICAL');
  });

  it('produces stable 16-hex fingerprints across runs', () => {
    const findings = [makeFinding('postinstall_network', 'high', 'evil@9.9.9', 'lib/install.js:4')];
    const fp1 = generateQfObject(findings).findings[0]!.fingerprint;
    const fp2 = generateQfObject(findings).findings[0]!.fingerprint;
    expect(fp1).toBe(fp2);
    expect(fp1).toMatch(/^[0-9a-f]{16}$/);
  });

  it('empty scan emits score 0 / CLEAN', () => {
    const qf = generateQfObject([]);
    expect(qf.score).toEqual({ value: 0, grade: 'CLEAN' });
    expect(qf.findings).toHaveLength(0);
  });

  it('formatQf round-trips through JSON.parse', () => {
    const parsed = JSON.parse(formatQf([makeFinding('postinstall_network', 'high')]));
    expect(parsed.schema).toBe('qf-findings/1');
  });
});
