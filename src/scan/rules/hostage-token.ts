/**
 * Rule 7: hostage_token
 *
 * Flags the "hostage token" worm shape first seen in tensorlake@0.5.144
 * (Mini Shai-Hulud, Oct 2026): the install hook steals a GitHub token, then
 * installs a monitor that checks the token every minute and wipes the home
 * directory the moment it stops working. Revoking the token first — the
 * normal incident-response move — is what pulls the trigger.
 *
 * Looks for:
 *  - known-compromised package versions
 *  - published indicators (monitor name, C2 domain, exfil repo description)
 *  - a token-validity check and a home-directory wipe in the same file
 *  - an install script that bootstraps the Bun runtime (how the Shai-Hulud
 *    family runs its payload outside Node, past Node-level monitoring)
 *
 * Severity: CRITICAL, except the Bun bootstrap alone (HIGH).
 * Every finding says to remove the package and its monitor BEFORE revoking.
 */

import * as path from 'node:path';
import type { Finding } from '../finding.js';
import type { Rule, PackageMeta } from '../types.js';
import { collectSourceFiles, readFileSafe, getScripts, evidenceAround, lineOf } from '../util.js';

export const REVOKE_WARNING =
  'Do NOT revoke tokens yet: remove the package and its gh-token-monitor first (run `chainwatch hostage-check`), then rotate.';

/** Versions published by the attacker. Name → bad versions. */
export const KNOWN_COMPROMISED: Record<string, string[]> = {
  tensorlake: ['0.5.144'],
};

/** Strings no legitimate package ships. */
const IOC_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /gh-token-monitor/, label: 'gh-token-monitor dead-man switch' },
  { re: /iseekaigogo\.com/i, label: 'tensorlake worm C2 domain' },
  { re: /Shai-Hulud: Here We Go Again/i, label: 'Shai-Hulud exfil repo description' },
];

// Checks whether a stolen GitHub token still works.
const TOKEN_CHECK_RE =
  /api\.github\.com\/user\b|gh\s+auth\s+status|Authorization['"]?\s*[:=]\s*[`'"](?:token|Bearer)\s/i;

// Wipes the user's home directory (POSIX shell, PowerShell, or Node).
const HOME_WIPE_RE = new RegExp(
  [
    String.raw`rm\s+-(?:rf|fr)\s+(?:~\/?|"?\$(?:HOME|\{HOME\})\/?"?)(?=[\s;&|'"\x60)]|$)`,
    String.raw`Remove-Item[^\n]{0,80}\$env:USERPROFILE[^\n]{0,40}-Recurse`,
    String.raw`Remove-Item[^\n]{0,40}-Recurse[^\n]{0,80}\$env:USERPROFILE`,
    String.raw`(?:rmSync|rmdirSync|rimraf(?:\.sync)?)\s*\(\s*(?:os\.)?homedir\(\)`,
  ].join('|'),
  'm',
);

// Fetches the Bun runtime at install time.
const BUN_BOOTSTRAP_RE = /bun\.sh\/install|github\.com\/oven-sh\/bun\/releases/;

const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];

export const hostageToken: Rule = {
  id: 'hostage_token',
  check(meta: PackageMeta): Finding[] {
    const findings: Finding[] = [];
    const pkgRef = `${meta.name}@${meta.version}`;

    if (KNOWN_COMPROMISED[meta.name]?.includes(meta.version)) {
      findings.push({
        rule: 'hostage_token',
        severity: 'critical',
        package: pkgRef,
        description: `Known-compromised release (token-stealing worm with wipe-on-revoke monitor). ${REVOKE_WARNING}`,
      });
    }

    const scripts = getScripts(meta.raw);
    const hasInstallScript = INSTALL_SCRIPTS.some((s) => scripts[s]);
    const scriptText = INSTALL_SCRIPTS.map((s) => scripts[s] ?? '').join('\n');

    const sources: { rel: string; content: string }[] = [{ rel: 'package.json', content: scriptText }];
    for (const file of collectSourceFiles(meta.path)) {
      const content = readFileSafe(file);
      if (content) sources.push({ rel: path.relative(meta.path, file), content });
    }

    for (const { rel, content } of sources) {
      const ioc = IOC_PATTERNS.find(({ re }) => re.test(content));
      if (ioc) {
        const m = content.match(ioc.re)![0];
        findings.push({
          rule: 'hostage_token',
          severity: 'critical',
          package: pkgRef,
          description: `Source contains ${ioc.label} indicator. ${REVOKE_WARNING}`,
          file: `${rel}:${lineOf(content, m)}`,
          evidence: evidenceAround(content, m),
        });
        continue; // one finding per file
      }

      const wipe = content.match(HOME_WIPE_RE);
      if (wipe && TOKEN_CHECK_RE.test(content)) {
        findings.push({
          rule: 'hostage_token',
          severity: 'critical',
          package: pkgRef,
          description: `Checks a GitHub token and wipes the home directory — dead-man switch. ${REVOKE_WARNING}`,
          file: `${rel}:${lineOf(content, wipe[0])}`,
          evidence: evidenceAround(content, wipe[0]),
        });
        continue;
      }

      const bun = hasInstallScript ? content.match(BUN_BOOTSTRAP_RE) : null;
      if (bun) {
        findings.push({
          rule: 'hostage_token',
          severity: 'high',
          package: pkgRef,
          description:
            'Package with install scripts downloads the Bun runtime — Shai-Hulud payload loader shape',
          file: `${rel}:${lineOf(content, bun[0])}`,
          evidence: evidenceAround(content, bun[0]),
        });
      }
    }

    return findings;
  },
};
