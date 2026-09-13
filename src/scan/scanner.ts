/**
 * Scanner — orchestrates detection rules over a node_modules directory.
 *
 * Discovers all installed packages, runs every rule against each, and returns
 * sorted findings. No concurrency in v1 — a 300-package scan runs in < 2s.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding, Severity } from './finding.js';
import { severityRank, meetsSeverity } from './finding.js';
import type { PackageMeta, RuleContext, RegistryMeta } from './types.js';
import { ALL_RULES } from './rules/index.js';

export interface ScanOptions {
  /** Minimum severity to include in results. */
  minSeverity?: Severity;
  /** Rules to run (defaults to ALL_RULES). */
  rules?: typeof ALL_RULES;
  /** Context passed to rules (package-lock, registry fetcher). */
  context?: RuleContext;
}

export interface ScanResult {
  findings: Finding[];
  packageCount: number;
  scanMs: number;
}

/**
 * Discover all packages in a node_modules directory by reading package.json
 * files. Handles scoped packages (@org/name), nested node_modules (version-
 * conflicted deps), and pnpm's .pnpm layout.
 */
export function discoverPackages(nodeModulesDir: string): PackageMeta[] {
  const packages: PackageMeta[] = [];
  const visited = new Set<string>();
  discoverInto(nodeModulesDir, packages, visited, 0);
  return packages;
}

function discoverInto(
  dir: string,
  packages: PackageMeta[],
  visited: Set<string>,
  depth: number,
  scope?: string,
): void {
  if (depth > 6 || !fs.existsSync(dir)) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    if (entry.name.startsWith('.')) continue;

    const pkgPath = path.join(dir, entry.name);

    if (entry.name.startsWith('@') && !scope) {
      // Scope directory — recurse one level.
      discoverInto(pkgPath, packages, visited, depth, entry.name);
      continue;
    }

    const meta = readPackageMeta(pkgPath, scope ? `${scope}/${entry.name}` : entry.name);
    if (!meta) continue;

    // Dedupe by real path — pnpm links can surface the same package twice.
    let real = pkgPath;
    try {
      real = fs.realpathSync(pkgPath);
    } catch { /* keep pkgPath */ }
    if (visited.has(real)) continue;
    visited.add(real);
    packages.push(meta);

    // Recurse into nested node_modules inside this package.
    discoverInto(path.join(pkgPath, 'node_modules'), packages, visited, depth + 1);
  }
}

function readPackageMeta(pkgPath: string, fallbackName: string): PackageMeta | null {
  const pkgJsonPath = path.join(pkgPath, 'package.json');
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  } catch {
    return null;
  }
  return {
    name: (raw['name'] as string) ?? fallbackName,
    version: (raw['version'] as string) ?? '0.0.0',
    path: pkgPath,
    raw,
  };
}

/**
 * Scan a node_modules directory. Runs all rules against all packages.
 */
export async function scan(nodeModulesDir: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const start = Date.now();
  const rules = opts.rules ?? ALL_RULES;
  const minSev = opts.minSeverity ?? 'low';

  // Load package-lock.json for rules that need it (dependency_confusion).
  let context: RuleContext = opts.context ?? {};
  if (!context.packageLock) {
    const lockPath = path.join(path.dirname(nodeModulesDir), 'package-lock.json');
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      context = { ...context, packageLock: lock };
    } catch {
      // No lock file — dependency_confusion rule will skip.
    }
  }
  context.projectDir ??= path.dirname(nodeModulesDir);

  // Set up a default registry fetcher if none provided.
  if (!context.fetchRegistryMeta) {
    context.fetchRegistryMeta = makeDefaultFetcher();
  }

  const packages = discoverPackages(nodeModulesDir);
  const findings: Finding[] = [];

  // Packages are independent — run them through a small concurrency pool so
  // registry-backed rules (suspicious_publish) don't serialize N HTTP calls.
  const POOL = 8;
  for (let i = 0; i < packages.length; i += POOL) {
    const chunk = packages.slice(i, i + POOL);
    const chunkResults = await Promise.all(
      chunk.map(async (pkg) => {
        const out: Finding[] = [];
        for (const rule of rules) {
          try {
            out.push(...(await rule.check(pkg, context)));
          } catch (e) {
            // A rule error shouldn't abort the whole scan.
            process.stderr.write(`chainwatch: rule ${rule.id} error on ${pkg.name}: ${(e as Error).message}\n`);
          }
        }
        return out;
      }),
    );
    for (const f of chunkResults) findings.push(...f);
  }

  // Filter by min severity and sort by severity descending.
  const filtered = findings
    .filter((f) => meetsSeverity(f.severity, minSev))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  return {
    findings: filtered,
    packageCount: packages.length,
    scanMs: Date.now() - start,
  };
}

/** Default registry fetcher — hits registry.npmjs.org. Cached per session.
 *  Uses https.request rather than fetch so no undici keep-alive socket is left
 *  closing when the CLI exits (a Windows process.exit race → 0xC0000409). */
function makeDefaultFetcher(): (name: string) => Promise<RegistryMeta | null> {
  const cache = new Map<string, RegistryMeta | null>();
  return async (name: string) => {
    if (cache.has(name)) return cache.get(name) ?? null;
    const meta = await fetchRegistryMeta(name);
    cache.set(name, meta);
    return meta;
  };
}

async function fetchRegistryMeta(name: string): Promise<RegistryMeta | null> {
  const { request } = await import('node:https');
  return new Promise((resolve) => {
    const req = request(
      `https://registry.npmjs.org/${encodeURIComponent(name)}`,
      { headers: { Accept: 'application/json' }, agent: false },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
              name?: string;
              /** npm's real field name is `time`, not `times`. */
              time?: Record<string, string>;
              maintainers?: { name: string }[] | string[];
              'dist-tags'?: Record<string, string>;
            };
            resolve({
              name: data.name ?? name,
              times: data.time ?? {},
              maintainers: (data.maintainers ?? []).map((m) =>
                typeof m === 'string' ? m : m.name,
              ),
              'dist-tags': data['dist-tags'] ?? {},
            });
          } catch {
            resolve(null);
          }
        });
        res.on('error', () => resolve(null));
      },
    );
    req.setTimeout(10_000, () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}
