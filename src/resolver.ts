/**
 * Package resolver — maps resolved file paths to npm package names.
 *
 * Node resolves symlinks in stack traces by default, so a package installed via
 * `file:` dependency, pnpm, or workspace links shows its REAL path (e.g.
 * `test/fixtures/fake-worm/index.js`) instead of `node_modules/fake-worm/index.js`.
 *
 * To attribute correctly, we scan `node_modules/` (including nested
 * node_modules inside packages) at startup, resolve each package directory's
 * real path, and build a prefix map: `realPath → packageName`.
 * During attribution, we match the frame's file path against this map.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

interface PkgEntry {
  /** Real (symlink-resolved) absolute path of the package directory. */
  realPath: string;
  /** Package name (`@scope/name` or `name`). */
  name: string;
}

/** Strip the Windows `\\?\` extended-length prefix that realpathSync returns. */
function stripUncPrefix(p: string): string {
  return p.startsWith('\\\\?\\') ? p.slice(4) : p;
}

/**
 * Extract the package name from a file path using the LAST `node_modules`
 * segment — handles nested node_modules (`foo/node_modules/bar`) and pnpm's
 * `.pnpm/<name>@<ver>/node_modules/<name>/` layout.
 */
export function packageNameFromPath(filePath: string): string | null {
  const parts = filePath.split(/[\\/]node_modules[\\/]/i);
  if (parts.length < 2) return null;
  const last = parts[parts.length - 1]!;
  const m = /^(?:@([^\\/]+)[\\/])?([^\\/]+)/.exec(last);
  if (!m) return null;
  const scope = m[1];
  const name = m[2] ?? '';
  if (name.startsWith('.')) return null; // e.g. .pnpm, .bin — not a package dir
  return scope ? `@${scope}/${name}` : name;
}

export class PackageResolver {
  /** Sorted by path length descending so longest prefix wins. */
  private entries: PkgEntry[] = [];
  private readonly nodeModulesPath: string;
  /** filePath → package name memo; hot path during recording. */
  private readonly cache = new Map<string, string | null>();
  /** Windows paths are case-insensitive — compare accordingly. */
  private readonly caseInsensitive = process.platform === 'win32';

  constructor(cwd: string = process.cwd()) {
    this.nodeModulesPath = path.join(cwd, 'node_modules');
  }

  /** Scan node_modules (incl. nested) and build the path map. Once at startup. */
  scan(): void {
    this.entries = [];
    this.cache.clear();
    if (!fs.existsSync(this.nodeModulesPath)) return;

    const visited = new Set<string>();

    const scanDir = (dir: string, depth: number, scope?: string) => {
      if (depth > 6) return;
      let entries: string[];
      try {
        entries = fs.readdirSync(dir);
      } catch {
        return;
      }
      for (const entry of entries) {
        // Skip pnpm internal dir and hidden dirs.
        if (entry.startsWith('.')) continue;

        const pkgDir = path.join(dir, entry);
        let stat;
        try {
          stat = fs.lstatSync(pkgDir);
        } catch {
          continue;
        }
        if (!stat.isDirectory() && !stat.isSymbolicLink()) continue;

        if (entry.startsWith('@') && !scope) {
          // Scope directory — recurse into it.
          scanDir(pkgDir, depth, entry);
          continue;
        }

        // Read package.json for the real name.
        const pkgJsonPath = path.join(pkgDir, 'package.json');
        let name = scope ? `${scope}/${entry}` : entry;
        try {
          const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
          if (pkg.name) name = pkg.name;
        } catch {
          // Fall back to directory-based name.
        }

        // Resolve symlinks to get the real path.
        let realPath: string;
        try {
          realPath = stripUncPrefix(fs.realpathSync(pkgDir));
        } catch {
          realPath = pkgDir;
        }

        this.entries.push({ realPath: realPath + path.sep, name });

        // Recurse into nested node_modules (version-conflicted deps).
        if (visited.has(realPath)) continue;
        visited.add(realPath);
        const nested = path.join(pkgDir, 'node_modules');
        try {
          if (fs.statSync(nested).isDirectory()) scanDir(nested, depth + 1);
        } catch { /* no nested node_modules */ }
      }
    };

    scanDir(this.nodeModulesPath, 0);

    // Sort by path length descending (longest prefix matches first).
    this.entries.sort((a, b) => b.realPath.length - a.realPath.length);
  }

  /**
   * Resolve a file path to its package name.
   * Returns null if the file is not inside any known package.
   */
  resolve(filePath: string): string | null {
    if (!filePath) return null;

    const cached = this.cache.get(filePath);
    if (cached !== undefined) return cached;

    const result = this.resolveUncached(stripUncPrefix(filePath));
    if (this.cache.size > 10_000) this.cache.clear(); // bound memory
    this.cache.set(filePath, result);
    return result;
  }

  private resolveUncached(filePath: string): string | null {
    // Fast path: package name from the last node_modules segment.
    const fast = packageNameFromPath(filePath);
    if (fast) return fast;

    // Slow path: check against resolved symlink targets.
    const normalized = filePath.replace(/\//g, path.sep);
    const cmp = this.caseInsensitive ? normalized.toLowerCase() : normalized;
    for (const entry of this.entries) {
      const target = this.caseInsensitive ? entry.realPath.toLowerCase() : entry.realPath;
      if (cmp.startsWith(target)) {
        return entry.name;
      }
    }

    return null;
  }
}
