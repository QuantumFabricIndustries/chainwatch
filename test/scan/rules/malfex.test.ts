/**
 * MALFEX campaign coverage — the Oct-2026 npm campaign shipped eight
 * packages carrying a RAT + a stealer for Discord tokens, browser
 * credentials and crypto wallets. Three were still installable with no
 * advisory, so signature feeds stay quiet — this is the behavioral case
 * ChainWatch exists for. These fixtures replay the documented shapes.
 */
import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { credentialFileAccess } from '../../../src/scan/rules/credential-file-access.js';
import { postinstallShell } from '../../../src/scan/rules/postinstall-shell.js';
import { postinstallNetwork } from '../../../src/scan/rules/postinstall-network.js';
import { obfuscationScore } from '../../../src/scan/rules/obfuscation-score.js';
import type { PackageMeta } from '../../../src/scan/types.js';

const FIXTURES = path.resolve(__dirname, '../../fixtures/node_modules');

function metaFor(name: string): PackageMeta {
  const pkgPath = path.join(FIXTURES, name);
  const raw = require(path.join(pkgPath, 'package.json'));
  return { name, version: raw.version ?? '0.0.0', path: pkgPath, raw };
}

describe('MALFEX stealer fixture', () => {
  it('flags Discord token store access', async () => {
    const findings = credentialFileAccess.check(metaFor('fake-malfex-stealer'));
    expect(findings.some((f) => f.description.toLowerCase().includes('discord'))).toBe(true);
  });

  it('flags browser credential databases', async () => {
    const findings = credentialFileAccess.check(metaFor('fake-malfex-stealer'));
    expect(findings.some((f) => f.description.toLowerCase().includes('browser credential'))).toBe(true);
  });

  it('flags crypto wallet / FTP / Telegram targets', async () => {
    const findings = credentialFileAccess.check(metaFor('fake-malfex-stealer'));
    const labels = findings.map((f) => f.description);
    expect(labels.some((d) => d.includes('crypto wallet'))).toBe(true);
    expect(labels.some((d) => d.includes('FileZilla') || d.includes('WinSCP'))).toBe(true);
    expect(labels.some((d) => d.includes('Telegram'))).toBe(true);
  });

  it('flags the install-script exfil + persistence', async () => {
    const net = postinstallNetwork.check(metaFor('fake-malfex-stealer'));
    const shell = postinstallShell.check(metaFor('fake-malfex-stealer'));
    expect(net.length + shell.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MALFEX RAT fixture', () => {
  it('flags C2 beacon + eval/exec payload', async () => {
    const net = postinstallNetwork.check(metaFor('fake-malfex-rat'));
    const shell = postinstallShell.check(metaFor('fake-malfex-rat'));
    const obf = obfuscationScore.check(metaFor('fake-malfex-rat'));
    expect(net.length + shell.length + obf.length).toBeGreaterThanOrEqual(1);
  });
});

describe('stealer-pattern false positives', () => {
  it('clean package still produces zero findings', async () => {
    const findings = credentialFileAccess.check(metaFor('fake-clean-pkg'));
    expect(findings).toEqual([]);
  });

  it('does not flag generic leveldb or cookie mentions without the path shape', async () => {
    // Rule is path-shaped: bare "leveldb" library usage or "cookies" text
    // must not trip it — the fixtures carry real path references only.
    const meta = metaFor('fake-clean-pkg');
    const findings = credentialFileAccess.check(meta);
    expect(findings.filter((f) => /leveldb|cookie/i.test(f.description))).toEqual([]);
  });
});
