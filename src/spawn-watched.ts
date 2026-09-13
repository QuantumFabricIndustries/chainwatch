import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';

/**
 * Spawn the watched/baselined command.
 *
 * On Windows, `spawn(cmd, args, { shell: true })` joins args into a cmd.exe
 * command line WITHOUT quoting (DEP0190), so a path like
 * `D:\my apps\script.cjs` is split at the space and fails. Instead we build
 * the command line ourselves with MSVCRT-compatible quoting and pass it as a
 * single string — this keeps .cmd/.bat shims (npm, npx) working through
 * cmd.exe while handling paths with spaces.
 *
 * On POSIX we spawn directly with an argv array (no shell needed).
 */
export function spawnWatched(cmdArgs: string[], opts: SpawnOptions): ChildProcess {
  const [cmd = '', ...rest] = cmdArgs;
  if (process.platform === 'win32') {
    const line = [cmd, ...rest].map(winQuote).join(' ');
    return spawn(line, { ...opts, shell: true });
  }
  return spawn(cmd, rest, opts);
}

/** Quote one argument for a cmd.exe command line (MSVCRT rules). */
function winQuote(arg: string): string {
  if (arg === '') return '""';
  if (!/[\s"&|<>^%()]/.test(arg)) return arg;
  // Backslashes preceding a quote are doubled; the quote is escaped; trailing
  // backslashes are doubled so they don't escape the closing quote.
  return `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1')}"`;
}
