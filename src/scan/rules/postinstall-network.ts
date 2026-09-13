/**
 * Rule 1: postinstall_network
 *
 * Flags install scripts (postinstall/preinstall/prepare) that make network
 * calls — a classic supply-chain attack vector. Looks for:
 *  - http.request, https.get, fetch, axios, got, node-fetch in script files
 *  - curl, wget in shell strings
 *  - base64-encoded URLs (common obfuscation)
 *
 * Severity: HIGH
 */

import * as path from 'node:path';
import type { Finding } from '../finding.js';
import type { Rule, PackageMeta } from '../types.js';
import { collectSourceFiles, readFileSafe, getScripts, evidenceAround, lineOf } from '../util.js';

const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

// Network-call patterns in JS source.
const JS_NETWORK_RE = /\b(?:https?\.(?:request|get)|fetch\(|axios|got\(|node-fetch|require\(['"](?:https?|http|axios|got|node-fetch)['"]\))/;
// Shell network tools.
const SHELL_NETWORK_RE = /\b(?:curl|wget)\b/;
// base64-encoded URLs — decode and check for http.
const BASE64_URL_RE = /[A-Za-z0-9+/]{20,}={0,2}/g;

function decodeBase64Maybe(s: string): string {
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf8');
    return /https?:\/\//.test(decoded) ? decoded : '';
  } catch {
    return '';
  }
}

export const postinstallNetwork: Rule = {
  id: 'postinstall_network',
  check(meta: PackageMeta): Finding[] {
    const findings: Finding[] = [];
    const scripts = getScripts(meta.raw);
    const pkgRef = `${meta.name}@${meta.version}`;

    // Which install scripts exist?
    const installScripts = INSTALL_SCRIPTS.filter((s) => scripts[s]);
    if (installScripts.length === 0) return findings;

    // Check the script strings themselves (shell commands in package.json).
    for (const scriptName of installScripts) {
      const scriptBody = scripts[scriptName] ?? '';
      if (SHELL_NETWORK_RE.test(scriptBody)) {
        findings.push({
          rule: 'postinstall_network',
          severity: 'high',
          package: pkgRef,
          description: `${scriptName} script invokes a network tool (curl/wget)`,
          evidence: evidenceAround(scriptBody, 'curl'),
        });
      }
      // base64 in the script string itself
      const b64matches = scriptBody.match(BASE64_URL_RE) ?? [];
      for (const b64 of b64matches) {
        const decoded = decodeBase64Maybe(b64);
        if (decoded) {
          findings.push({
            rule: 'postinstall_network',
            severity: 'high',
            package: pkgRef,
            description: `${scriptName} script contains base64-encoded URL: ${decoded.slice(0, 60)}`,
            evidence: b64,
          });
        }
      }
    }

    // Files the install scripts actually invoke (e.g. `node install.js`) get
    // HIGH severity; network code elsewhere in the package is only MEDIUM —
    // plenty of legit packages have a postinstall AND http code (telemetry,
    // download mirrors), which used to FP as HIGH.
    const referenced = new Set<string>();
    for (const scriptName of installScripts) {
      const body = scripts[scriptName] ?? '';
      for (const m of body.matchAll(/([\w./-]+\.(?:js|mjs|cjs|ts))/g)) {
        referenced.add(m[1]!.replace(/^\.\//, ''));
      }
    }

    // Check JS source files referenced by or co-located with install scripts.
    const sourceFiles = collectSourceFiles(meta.path);
    for (const file of sourceFiles) {
      const content = readFileSafe(file);
      if (!content) continue;
      const relFile = path.relative(meta.path, file);

      if (JS_NETWORK_RE.test(content)) {
        const match = content.match(JS_NETWORK_RE);
        const matchStr = match?.[0] ?? '';
        const relNorm = relFile.replace(/\\/g, '/');
        const isInstallFile = referenced.has(relNorm) || referenced.has(`./${relNorm}`);
        findings.push({
          rule: 'postinstall_network',
          severity: isInstallFile ? 'high' : 'medium',
          package: pkgRef,
          description: isInstallFile
            ? `Install script file makes network call (${matchStr})`
            : `Package with install scripts contains network code (${matchStr})`,
          file: `${relFile}:${lineOf(content, matchStr)}`,
          evidence: evidenceAround(content, matchStr),
        });
      }

      // base64-encoded URLs in source
      const b64matches = content.match(BASE64_URL_RE) ?? [];
      for (const b64 of b64matches) {
        const decoded = decodeBase64Maybe(b64);
        if (decoded) {
          findings.push({
            rule: 'postinstall_network',
            severity: 'high',
            package: pkgRef,
            description: `Source contains base64-encoded URL: ${decoded.slice(0, 60)}`,
            file: `${relFile}:${lineOf(content, b64)}`,
            evidence: b64,
          });
          break; // one per file is enough
        }
      }
    }

    return findings;
  },
};
