/**
 * Rule 5: suspicious_publish
 *
 * Cross-references the installed package version against npm registry metadata:
 *  - Version published < 48 hours ago
 *  - Publishing maintainer has < 3 prior published packages
 *  - Package name is a typosquat (Levenshtein < 2 from a top package)
 *
 * Uses an injectable fetcher so tests don't hit the real registry.
 *
 * Severity: MEDIUM (new publish alone), HIGH (new + typosquat), CRITICAL
 * (typosquat + new publish by brand-new maintainer)
 */

import type { Finding } from '../finding.js';
import type { Rule, PackageMeta, RuleContext, RegistryMeta } from '../types.js';

const FORTY_EIGHT_HRS_MS = 48 * 60 * 60 * 1000;

// A small set of common package names for typosquat detection. In production
// this would be the top-500; for v1 a representative sample catches the pattern.
const TOP_PACKAGES = new Set([
  'lodash', 'react', 'axios', 'chalk', 'commander', 'express', 'request',
  'moment', 'typescript', 'ts-node', 'vue', 'angular', 'jquery', 'bootstrap',
  'webpack', 'babel', 'eslint', 'jest', 'mocha', 'dotenv', 'fs-extra',
  'node-fetch', 'got', 'rxjs', 'underscore', 'async', 'bluebird', 'uuid',
  'validator', 'yup', 'zod', 'prisma', 'mongoose', 'sequelize', 'knex',
]);

// Known-good packages that are legitimately 1–2 edits from a top package.
// Without this allowlist, chai (→chalk), vite (→vue), tsup (→yup) etc. would
// false-positive as typosquats. These are established packages with millions
// of weekly downloads.
const TYPOSQUAT_ALLOWLIST = new Set([
  'chai', 'vite', 'vite-node', 'tsup', 'tsx', 'vitest', 'chalk',
  '@types/node', '@types/react', '@types/express', '@types/jest',
  '@vitest/pretty-format', '@vitest/expect', '@vitest/spy',
  '@vitest/utils', '@vitest/runner', '@vitest/snapshot',
]);

/** Levenshtein distance — small strings only (package names). */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i]![0] = i;
  for (let j = 0; j <= n; j++) dp[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(
        (dp[i - 1]![j] ?? 0) + 1,
        (dp[i]![j - 1] ?? 0) + 1,
        (dp[i - 1]![j - 1] ?? 0) + cost,
      );
    }
  }
  return dp[m]![n] ?? 0;
}

/** Check if a name is a typosquat of any top package (distance <= 2). */
function typosquatOf(name: string): { top: string; distance: number } | null {
  // Skip known-good packages that happen to be close to a top package name.
  if (TYPOSQUAT_ALLOWLIST.has(name)) return null;
  const base = name.startsWith('@') ? name.split('/')[1] ?? '' : name;
  for (const top of TOP_PACKAGES) {
    if (base === top) continue; // exact match is not a typosquat
    if (Math.abs(base.length - top.length) > 2) continue;
    const d = levenshtein(base, top);
    if (d <= 2) return { top, distance: d };
  }
  return null;
}

export const suspiciousPublish: Rule = {
  id: 'suspicious_publish',
  async check(meta: PackageMeta, ctx?: RuleContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const pkgRef = `${meta.name}@${meta.version}`;
    const fetcher = ctx?.fetchRegistryMeta;

    // Typosquat check — doesn't need registry.
    const typo = typosquatOf(meta.name);
    if (typo) {
      findings.push({
        rule: 'suspicious_publish',
        severity: 'medium',
        package: pkgRef,
        description: `Package name "${meta.name}" is a likely typosquat of "${typo.top}" (Levenshtein distance ${typo.distance})`,
      });
    }

    // Registry checks — need a fetcher.
    if (!fetcher) return findings;

    let regMeta: RegistryMeta | null = null;
    try {
      regMeta = await fetcher(meta.name);
    } catch {
      return findings; // registry unreachable — don't block scan
    }
    if (!regMeta) return findings;
    if (!regMeta.times || !regMeta.maintainers) return findings;

    const publishTime = regMeta.times[meta.version];
    const isNew = publishTime && Date.now() - new Date(publishTime).getTime() < FORTY_EIGHT_HRS_MS;
    const maintainerCount = regMeta.maintainers.length;

    if (isNew && maintainerCount < 3) {
      const sev = typo ? 'critical' : 'high';
      findings.push({
        rule: 'suspicious_publish',
        severity: sev,
        package: pkgRef,
        description: `Version published ${hoursAgo(publishTime)} ago by a maintainer with ${maintainerCount} prior publish(s)${typo ? ' + typosquat' : ''}`,
        evidence: `published: ${publishTime}`,
      });
    } else if (isNew) {
      findings.push({
        rule: 'suspicious_publish',
        severity: 'medium',
        package: pkgRef,
        description: `Version published ${hoursAgo(publishTime)} ago (recent)`,
        evidence: `published: ${publishTime}`,
      });
    }

    return findings;
  },
};

function hoursAgo(iso: string): string {
  const hrs = (Date.now() - new Date(iso).getTime()) / (60 * 60 * 1000);
  return hrs < 1 ? `${Math.round(hrs * 60)} minutes` : `${Math.round(hrs)} hours`;
}
