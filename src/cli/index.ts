#!/usr/bin/env node
/**
 * chainwatch CLI entry point.
 */

import { Command } from 'commander';
import { registerScan } from './commands/scan.js';
import { registerWatch } from './commands/watch.js';
import { registerBaseline } from './commands/baseline.js';
import { registerSync } from './commands/sync.js';
import { registerHostage } from './commands/hostage.js';
import { runDemo } from '../demo.js';

const program = new Command();

program
  .name('chainwatch')
  .description('npm supply-chain runtime watchdog')
  .version('1.0.0');

registerScan(program);
registerWatch(program);
registerBaseline(program);
registerSync(program);
registerHostage(program);

// Keep the demo as a hidden command for backwards compat.
program
  .command('demo', { hidden: true })
  .action(async () => {
    await runDemo();
  });

program.parse();
