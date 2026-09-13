/**
 * worker_threads interceptor — closes the fresh-registry bypass.
 *
 * A `new Worker()` gets its own module registry: our patched fs/net exports
 * don't exist inside it. To fix that, we inject the ChainWatch preload into
 * the worker's `execArgv` so interception reinstalls inside the worker.
 * (Workers can't receive NODE_OPTIONS after the parent started.)
 *
 * The spawn itself is intentionally NOT reported — workers are routine for
 * build tools, and a false shell_spawn signal could push a benign
 * credential-read → worker chain over the block threshold.
 */

import { createRequire } from 'node:module';
import type { Engine } from '../engine.js';

const require = createRequire(import.meta.url);
const wt = require('node:worker_threads');

const PRELOAD_ENV = 'CHAINWATCH_PRELOAD_URL';

let originalWorker: typeof wt.Worker | null = null;
let patched = false;

/**
 * Patch Worker so each worker re-imports the preload URL stored in
 * CHAINWATCH_PRELOAD_URL (set by `watch`/`baseline record` to the active
 * preload — preload.js or recorder-preload.js).
 * Idempotent — a second call (engine + recorder both installed) doesn't stack
 * another wrapper that unpatch couldn't fully restore.
 */
export function injectWorkerPreload(): void {
  if (patched) return;
  const preloadUrl = process.env[PRELOAD_ENV];
  if (!preloadUrl) return;
  const Original = wt.Worker;
  if (typeof Original !== 'function') return;
  originalWorker = Original;
  patched = true;

  wt.Worker = class PatchedWorker extends Original {
    constructor(filename: string | URL, options: any = {}) {
      const execArgv = Array.isArray(options.execArgv)
        ? [...options.execArgv]
        : [...process.execArgv];
      if (!execArgv.includes(preloadUrl)) {
        execArgv.push('--import', preloadUrl);
      }
      super(filename, { ...options, execArgv });
    }
  } as typeof Original;
}

export function unpatchWorker(): void {
  if (originalWorker) {
    wt.Worker = originalWorker;
    originalWorker = null;
  }
  patched = false;
}

export function installWorker(_engine: Engine): void {
  injectWorkerPreload();
}

export function uninstallWorker(): void {
  unpatchWorker();
}
