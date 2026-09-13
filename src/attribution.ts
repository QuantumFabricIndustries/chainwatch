/**
 * Package attribution via call-stack resolution.
 *
 * When an intercepted core-module function is called, we walk the call stack
 * to find the first frame that lives inside a package. That package is the one
 * making the call — perfect attribution without any cooperation from the
 * package itself.
 *
 * Attribution uses two strategies:
 *  1. Fast path: last `node_modules/<pkg>/` segment in the file path
 *     (handles nested node_modules and pnpm's .pnpm layout).
 *  2. Slow path: prefix match against the PackageResolver's symlink-resolved
 *     path map (handles `file:` deps and workspace links).
 */

import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import type { PackageResolver } from './resolver.js';
import { packageNameFromPath } from './resolver.js';

// ChainWatch's own module directory — used to skip our own frames. Anchored to
// the actual module location so a USER project that happens to live in a
// directory named "chainwatch" is still attributed correctly.
const SELF_DIR = path.dirname(fileURLToPath(import.meta.url));
const SELF_RE = /[\\/]node_modules[\\/]chainwatch[\\/]/;

// The default stackTraceLimit (10) is too shallow for attribution through
// promise chains and framework internals. Raising it here is process-wide but
// harmless — Error.stack strings just get longer.
if (Error.stackTraceLimit < 50) Error.stackTraceLimit = 50;

export interface Attribution {
  /** Package name (`@scope/name` or `name`), or `<entry>` / `<unknown>`. */
  package: string;
  /** The file path of the attributed frame, for forensics. */
  file: string;
  /** Full serialized stack. */
  stack: string;
}

/**
 * Capture the raw call sites for the current point of execution.
 * Temporarily swaps `Error.prepareStackTrace` to get structured frames.
 */
function captureCallSites(): NodeJS.CallSite[] {
  const oldPrepare = Error.prepareStackTrace;
  Error.prepareStackTrace = (_err, sites) => sites;
  const err = new Error();
  const sites = err.stack as unknown as NodeJS.CallSite[];
  Error.prepareStackTrace = oldPrepare;
  return sites ?? [];
}

function isSelfFile(file: string): boolean {
  const f = file.replace(/\//g, path.sep);
  return f.startsWith(SELF_DIR + path.sep) || SELF_RE.test(file);
}

/**
 * Resolve the package responsible for the current call.
 *
 * Walks from the top of the stack (most recent frame) downward, skipping
 * ChainWatch's own frames and Node core frames, and returns the first frame
 * that can be attributed to a package.
 */
export function attributeCall(resolver?: PackageResolver): Attribution {
  const sites = captureCallSites();
  let entryFile = '';

  for (const site of sites) {
    const file = site.getFileName?.() ?? '';
    if (!file) continue;

    // Skip Node core modules (node:fs, internal/...).
    if (file.startsWith('node:') || file.includes('internal/')) continue;
    // Skip ChainWatch's own source.
    if (isSelfFile(file)) continue;

    // Track the first non-core, non-self file as the entry candidate.
    if (!entryFile) entryFile = file;

    // Try the resolver first (handles symlinks), then fall back to regex.
    if (resolver) {
      const pkg = resolver.resolve(file);
      if (pkg) {
        return { package: pkg, file, stack: serialize(sites) };
      }
    }

    const pkg = packageNameFromPath(file);
    if (pkg) {
      return { package: pkg, file, stack: serialize(sites) };
    }
  }

  // No package frame — the call came from the entry script or unknown.
  return {
    package: entryFile ? '<entry>' : '<unknown>',
    file: entryFile,
    stack: serialize(sites),
  };
}

function serialize(sites: NodeJS.CallSite[]): string {
  return sites
    .slice(0, 40)
    .map((s) => `    at ${s.toString()}`)
    .join('\n');
}
