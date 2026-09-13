/**
 * ChainWatch preload — loaded via `node --import chainwatch/preload` to start
 * the runtime interceptor before the user's code runs.
 *
 * Events are written to a JSONL file (path from CHAINWATCH_EVENT_LOG env var)
 * so the parent `chainwatch watch` process can display them in real time.
 *
 * Policy is built from chainwatch.config.json (if present) plus env vars set
 * by the `watch` command (CHAINWATCH_BLOCK_ON, CHAINWATCH_TRUSTED,
 * CHAINWATCH_ALLOW_HOSTS).
 */

import * as fs from 'node:fs';
import { Engine, type ChainWatchEvent } from './index.js';
import { buildPolicy } from './config.js';

const eventLogPath = process.env['CHAINWATCH_EVENT_LOG'];

const engine = new Engine(buildPolicy());
engine.install();

if (eventLogPath) {
  engine.onEvent((e: ChainWatchEvent) => {
    try {
      fs.appendFileSync(eventLogPath, JSON.stringify(e) + '\n');
    } catch {
      // Best effort — don't crash the watched process.
    }
  });
}

// Export for programmatic use.
export { engine };
