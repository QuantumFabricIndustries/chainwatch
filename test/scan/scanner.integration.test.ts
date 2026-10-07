import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { scan, discoverPackages } from '../../src/scan/scanner.js';

const FIXTURES = path.resolve(__dirname, '../fixtures/node_modules');

describe('Scanner integration', () => {
  it('discovers all fixture packages', () => {
    const packages = discoverPackages(FIXTURES);
    const names = packages.map((p) => p.name).sort();
    expect(names).toContain('fake-clean-pkg');
    expect(names).toContain('fake-postinstall-network');
    expect(names).toContain('fake-postinstall-shell');
    expect(names).toContain('fake-credential-reader');
    expect(names).toContain('fake-obfuscated');
    expect(names).toContain('lodahs'); // fake-typosquat fixture has name "lodahs"
    expect(names).toContain('@myorg/internal-lib'); // fake-dependency-confusion fixture
    expect(names).toContain('fake-malfex-stealer');
    expect(names).toContain('fake-malfex-rat');
    expect(packages.length).toBeGreaterThanOrEqual(9);
  });

  it('produces findings for malicious fixtures but not clean ones', async () => {
    // Use a stub fetcher so we don't hit the real registry.
    const result = await scan(FIXTURES, {
      minSeverity: 'low',
      context: {
        fetchRegistryMeta: async () => null,
      },
    });

    // Clean package should have no findings.
    const cleanFindings = result.findings.filter((f) => f.package.startsWith('fake-clean-pkg'));
    expect(cleanFindings).toEqual([]);

    // Malicious packages should have findings.
    const pkgNames = result.findings.map((f) => f.package);
    expect(pkgNames.some((p) => p.startsWith('fake-postinstall-shell'))).toBe(true);
    expect(pkgNames.some((p) => p.startsWith('fake-postinstall-network'))).toBe(true);
    expect(pkgNames.some((p) => p.startsWith('fake-credential-reader'))).toBe(true);
    expect(pkgNames.some((p) => p.startsWith('fake-obfuscated'))).toBe(true);
    // Typosquat fixture has name "lodahs" — should be flagged by suspicious_publish.
    expect(pkgNames.some((p) => p.startsWith('lodahs'))).toBe(true);
    // MALFEX fixtures: stealer + RAT must produce findings.
    expect(pkgNames.some((p) => p.startsWith('fake-malfex-stealer'))).toBe(true);
    expect(pkgNames.some((p) => p.startsWith('fake-malfex-rat'))).toBe(true);
  });

  it('sorts findings by severity descending', async () => {
    const result = await scan(FIXTURES, {
      minSeverity: 'low',
      context: { fetchRegistryMeta: async () => null },
    });
    const ranks = result.findings.map((f) => {
      const map = { low: 1, medium: 2, high: 3, critical: 4 };
      return map[f.severity];
    });
    for (let i = 1; i < ranks.length; i++) {
      expect(ranks[i]).toBeLessThanOrEqual(ranks[i - 1]!);
    }
  });
});
