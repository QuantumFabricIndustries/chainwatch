/**
 * Rule 6: dependency_confusion
 *
 * Detects the classic dependency-confusion attack: a scoped package `@org/pkg`
 * is installed from the PUBLIC npm registry when the org intended it to come
 * from their PRIVATE registry. The attack works by publishing a higher-version
 * public package with the same scoped name.
 *
 * Detection:
 *  - Package has a scope (`@org/...`)
 *  - package-lock.json shows it resolved from registry.npmjs.org (public)
 *    when a private registry is configured in .npmrc for that scope
 *
 * Severity: CRITICAL
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding } from '../finding.js';
import type { Rule, PackageMeta, RuleContext } from '../types.js';

interface LockEntry {
  resolved?: string;
  version?: string;
}

export const dependencyConfusion: Rule = {
  id: 'dependency_confusion',
  check(meta: PackageMeta, ctx?: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const pkgRef = `${meta.name}@${meta.version}`;

    // Only scoped packages can be confusion-attacked.
    if (!meta.name.startsWith('@')) return findings;

    const scope = meta.name.split('/')[0]!; // @org

    // Check .npmrc for a private registry configured for this scope.
    // Resolved relative to the scanned project, not wherever chainwatch ran.
    const projectDir = ctx?.projectDir ?? process.cwd();
    const npmrcPath = path.join(projectDir, '.npmrc');
    let hasPrivateRegistry = false;
    let privateRegistry = '';
    try {
      const npmrc = fs.readFileSync(npmrcPath, 'utf8');
      const m = npmrc.match(new RegExp(`${scope}:registry=(\\S+)`));
      if (m) {
        hasPrivateRegistry = true;
        privateRegistry = m[1] ?? '';
      }
    } catch {
      // No .npmrc — can't determine private registry config.
    }

    if (!hasPrivateRegistry) return findings;

    // Check package-lock.json for where this package resolved from.
    const lock = ctx?.packageLock;
    if (!lock) return findings;

    const packages = (lock['packages'] ?? lock['dependencies'] ?? {}) as Record<string, LockEntry>;
    const lockEntry = packages[meta.name] ?? packages[`node_modules/${meta.name}`];
    const resolved = lockEntry?.resolved ?? '';

    // If it resolved from the public npm registry but a private one is configured,
    // that's a dependency-confusion attack.
    if (resolved.includes('registry.npmjs.org') && !resolved.includes(privateRegistry)) {
      findings.push({
        rule: 'dependency_confusion',
        severity: 'critical',
        package: pkgRef,
        description: `Scoped package "${meta.name}" resolved from public npm registry but a private registry is configured for ${scope}`,
        evidence: `resolved: ${resolved}`,
      });
    }

    return findings;
  },
};
