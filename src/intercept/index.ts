/**
 * Interceptor installer — registers all core-module wrappers with the engine.
 *
 * Registered with the Engine via `registerInstallers` so the engine module
 * doesn't need to know about individual interceptors (avoids circular deps).
 */

import { registerInstallers } from '../engine.js';
import type { Engine } from '../engine.js';
import { installFs, uninstallFs } from './fs.js';
import { installNet, uninstallNet } from './net.js';
import { installChildProcess, uninstallChildProcess } from './child_process.js';
import { installWorker, uninstallWorker } from './worker.js';

function install(engine: Engine): void {
  installFs(engine);
  installNet(engine);
  installChildProcess(engine);
  installWorker(engine);
}

function uninstall(engine: Engine): void {
  uninstallFs();
  uninstallNet();
  uninstallChildProcess();
  uninstallWorker();
}

registerInstallers(install, uninstall);

export { install, uninstall };
