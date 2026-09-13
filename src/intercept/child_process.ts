/**
 * child_process interceptor — detects shell spawns and self-propagation.
 *
 * Wraps exec/execSync/execFile/execFileSync/spawn/spawnSync/fork. Any shell
 * spawn fires `shell_spawn`. Commands that publish or enumerate npm tokens
 * escalate to `self_propagation` (the worm tell); commands that run nested
 * package installs fire `install_script`. Throws on block.
 *
 * For spawn/execFile the command is args[0] and arguments are args[1] — we
 * check BOTH, because `spawn('npm', ['publish'])` is the normal form.
 */

import { createRequire } from 'node:module';
import { ChainWatchBlockError, type Engine } from '../engine.js';
import type { SignalType } from '../events.js';

const require = createRequire(import.meta.url);
const cp = require('node:child_process');

type AnyFn = (...args: any[]) => any;

interface Restore {
  obj: any;
  name: string;
  fn: AnyFn;
}
const originals: Restore[] = [];

const PROPAGATION_RE = /\b(?:npm\s+(?:publish|login|whoami|token|adduser|access)|yarn\s+publish|pnpm\s+publish|npx\s+npm\s+publish)\b/i;
const INSTALL_RE = /\b(?:npm|pnpm|yarn)\s+(?:install|i|ci|add|create)\b/i;

function wrap(name: string, engine: Engine): void {
  const original = cp[name] as AnyFn;
  originals.push({ obj: cp, name, fn: original });
  cp[name] = function patched(...args: any[]): any {
    const cmd = String(args[0] ?? '');
    const argv = Array.isArray(args[1]) ? args[1].join(' ') : '';
    const full = argv ? `${cmd} ${argv}` : cmd;

    const signal: SignalType = PROPAGATION_RE.test(full)
      ? 'self_propagation'
      : INSTALL_RE.test(full)
        ? 'install_script'
        : 'shell_spawn';

    const { action, event } = engine.evaluate(
      signal,
      engine.policy.baseSeverity[signal],
      engine.policy.baseScore[signal],
      { command: full },
    );
    if (action === 'block') throw new ChainWatchBlockError(event);
    return original.apply(this, args);
  };
}

export function installChildProcess(engine: Engine): void {
  wrap('exec', engine);
  wrap('execSync', engine);
  wrap('execFile', engine);
  wrap('execFileSync', engine);
  wrap('spawn', engine);
  wrap('spawnSync', engine);
  wrap('fork', engine);
}

export function uninstallChildProcess(): void {
  for (const { obj, name, fn } of originals.splice(0)) {
    obj[name] = fn;
  }
}
