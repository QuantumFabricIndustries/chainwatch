/**
 * fs interceptor — detects credential-file access.
 *
 * Wraps the read-path functions on the CJS `fs` module AND `fs.promises` /
 * `node:fs/promises` (same object under the hood). When a package reads a file
 * matching a credential pattern (`.npmrc`, `.ssh/`, `.env`, `.aws/`, etc.) or
 * enumerates a credential directory, fires `credential_access`. Throws
 * ChainWatchBlockError if the engine decides to block (high chain score).
 */

import { createRequire } from 'node:module';
import { ChainWatchBlockError, type Engine } from '../engine.js';

const require = createRequire(import.meta.url);
const fs = require('node:fs');

type AnyFn = (...args: any[]) => any;

interface Restore {
  obj: any;
  name: string;
  fn: AnyFn;
}
const originals: Restore[] = [];

function wrapRead(obj: any, name: string, engine: Engine, isDir = false): void {
  const original = obj?.[name] as AnyFn | undefined;
  if (typeof original !== 'function') return;
  originals.push({ obj, name, fn: original });
  obj[name] = function patched(...args: any[]): any {
    const path = String(args[0] ?? '');
    checkCredential(path, engine, isDir);
    return original.apply(this, args);
  };
}

function checkCredential(path: string, engine: Engine, isDir = false): void {
  // Directory patterns like /\.ssh\// need a trailing separator to match.
  const probe = isDir && !/[\\/]$/.test(path) ? `${path}/` : path;
  for (const re of engine.policy.credentialPatterns) {
    if (re.test(probe)) {
      const { action, event } = engine.evaluate(
        'credential_access',
        'high',
        engine.policy.baseScore.credential_access,
        { file: path, pattern: re.source, access: isDir ? 'enumerate' : 'read' },
      );
      if (action === 'block') throw new ChainWatchBlockError(event);
      return;
    }
  }
}

export function installFs(engine: Engine): void {
  wrapRead(fs, 'readFileSync', engine);
  wrapRead(fs, 'readFile', engine);
  wrapRead(fs, 'openSync', engine);
  wrapRead(fs, 'open', engine);
  wrapRead(fs, 'createReadStream', engine);
  // Existence/metadata probes — worm reconnaissance on credential files.
  wrapRead(fs, 'statSync', engine);
  wrapRead(fs, 'stat', engine);
  wrapRead(fs, 'accessSync', engine);
  wrapRead(fs, 'access', engine);
  wrapRead(fs, 'existsSync', engine);
  // Directory enumeration (~/.ssh/, ~/.aws/).
  wrapRead(fs, 'readdirSync', engine, true);
  wrapRead(fs, 'readdir', engine, true);

  // fs.promises / node:fs/promises — the same exports object, but covered
  // explicitly so ESM `import { readFile } from 'fs/promises'` is caught too.
  const promises = fs.promises;
  if (promises) {
    wrapRead(promises, 'readFile', engine);
    wrapRead(promises, 'open', engine);
    wrapRead(promises, 'stat', engine);
    wrapRead(promises, 'access', engine);
    wrapRead(promises, 'readdir', engine, true);
  }
}

export function uninstallFs(): void {
  for (const { obj, name, fn } of originals.splice(0)) {
    obj[name] = fn;
  }
}
