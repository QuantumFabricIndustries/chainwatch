import { describe, it, expect } from 'vitest';
import { generateSarifObject, getRuleId, formatSarif } from '../../src/reporter/sarif.js';
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

describe('SARIF reporter', () => {
  it('generates valid SARIF 2.1.0 structure', () => {
    const findings = [makeFinding('postinstall_network', 'high')];
    const sarif = generateSarifObject(findings);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.name).toBe('ChainWatch');
  });

  it('maps rule names to stable CWxxx IDs', () => {
    expect(getRuleId('postinstall_network')).toBe('CW001');
    expect(getRuleId('postinstall_shell')).toBe('CW002');
    expect(getRuleId('credential_file_access')).toBe('CW003');
    expect(getRuleId('obfuscation_score')).toBe('CW004');
    expect(getRuleId('suspicious_publish')).toBe('CW005');
    expect(getRuleId('dependency_confusion')).toBe('CW006');
    expect(getRuleId('behavioral_drift')).toBe('CW007');
    expect(getRuleId('hostage_token')).toBe('CW008');
  });

  it('includes all 8 rules in the tool driver', () => {
    const findings = [makeFinding('postinstall_network', 'high')];
    const sarif = generateSarifObject(findings);
    const ruleIds = sarif.runs[0]!.tool.driver.rules.map((r) => r.id);
    expect(ruleIds).toContain('CW001');
    expect(ruleIds).toContain('CW002');
    expect(ruleIds).toContain('CW003');
    expect(ruleIds).toContain('CW004');
    expect(ruleIds).toContain('CW005');
    expect(ruleIds).toContain('CW006');
    expect(ruleIds).toContain('CW007');
    expect(ruleIds).toContain('CW008');
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(8);
  });

  it('maps severity to SARIF level correctly', () => {
    const critical = generateSarifObject([makeFinding('postinstall_shell', 'critical')]);
    const high = generateSarifObject([makeFinding('postinstall_network', 'high')]);
    const medium = generateSarifObject([makeFinding('obfuscation_score', 'medium')]);
    const low = generateSarifObject([makeFinding('suspicious_publish', 'low')]);

    expect(critical.runs[0]!.results[0]!.level).toBe('error');
    expect(high.runs[0]!.results[0]!.level).toBe('error');
    expect(medium.runs[0]!.results[0]!.level).toBe('warning');
    expect(low.runs[0]!.results[0]!.level).toBe('note');
  });

  it('sets defaultConfiguration level for each rule', () => {
    const findings: Finding[] = [];
    const sarif = generateSarifObject(findings);
    const rules = sarif.runs[0]!.tool.driver.rules;
    const byId = new Map(rules.map((r) => [r.id, r]));

    // CW001, CW002, CW003, CW006 are error (high/critical rules)
    expect(byId.get('CW001')!.defaultConfiguration.level).toBe('error');
    expect(byId.get('CW002')!.defaultConfiguration.level).toBe('error');
    expect(byId.get('CW003')!.defaultConfiguration.level).toBe('error');
    expect(byId.get('CW006')!.defaultConfiguration.level).toBe('error');
    // CW004, CW005, CW007 are warning (medium rules)
    expect(byId.get('CW004')!.defaultConfiguration.level).toBe('warning');
    expect(byId.get('CW005')!.defaultConfiguration.level).toBe('warning');
    expect(byId.get('CW007')!.defaultConfiguration.level).toBe('warning');
  });

  it('includes rule metadata (name, description, helpUri)', () => {
    const sarif = generateSarifObject([]);
    const rule = sarif.runs[0]!.tool.driver.rules.find((r) => r.id === 'CW001');
    expect(rule).toBeDefined();
    expect(rule!.name).toBe('PostinstallNetwork');
    expect(rule!.shortDescription.text).toBe('Postinstall script makes network request');
    expect(rule!.helpUri).toBe('https://chainwatch.dev/rules/CW001');
  });

  it('includes locations with uriBaseId', () => {
    const findings = [makeFinding('credential_file_access', 'high', 'evil@1.0.0', 'node_modules/evil/index.js:14')];
    const sarif = generateSarifObject(findings);
    const result = sarif.runs[0]!.results[0]!;
    expect(result.locations).toHaveLength(1);
    expect(result.locations[0]!.physicalLocation.artifactLocation.uri).toBe('node_modules/evil/index.js');
    expect(result.locations[0]!.physicalLocation.artifactLocation.uriBaseId).toBe('%SRCROOT%');
    expect(result.locations[0]!.physicalLocation.region?.startLine).toBe(14);
  });

  it('parses Windows paths without corrupting the drive letter', () => {
    // C:\project\file.js:10 — a naive split(':') would produce uri 'C'.
    const findings = [makeFinding('credential_file_access', 'high', 'evil@1.0.0', 'C:\\project\\file.js:10')];
    const sarif = generateSarifObject(findings);
    const loc = sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation;
    expect(loc.artifactLocation.uri).toBe('C:/project/file.js');
    expect(loc.region?.startLine).toBe(10);
  });

  it('handles Windows paths with no line number', () => {
    const findings = [makeFinding('obfuscation_score', 'medium', 'evil@1.0.0', 'D:\\pkg\\dist\\bundle.js')];
    const sarif = generateSarifObject(findings);
    const loc = sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation;
    expect(loc.artifactLocation.uri).toBe('D:/pkg/dist/bundle.js');
    expect(loc.region).toBeUndefined();
  });

  it('points findings with no file at the package manifest (code scanning needs a location)', () => {
    const findings = [makeFinding('suspicious_publish', 'medium')];
    const sarif = generateSarifObject(findings);
    const result = sarif.runs[0]!.results[0]!;
    expect(result.locations[0]!.physicalLocation.artifactLocation.uri).toBe('node_modules/test-pkg/package.json');
    expect(result.locations[0]!.physicalLocation.region).toBeUndefined();
  });

  it('produces valid JSON from formatSarif', () => {
    const findings = [makeFinding('postinstall_network', 'high')];
    const json = formatSarif(findings);
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json);
    expect(parsed.version).toBe('2.1.0');
  });

  it('includes tool version', () => {
    const sarif = generateSarifObject([], '2.0.0');
    expect(sarif.runs[0]!.tool.driver.version).toBe('2.0.0');
  });

  it('handles empty findings (no results, all rules present)', () => {
    const sarif = generateSarifObject([]);
    expect(sarif.runs[0]!.results).toEqual([]);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(8);
  });
});
