/**
 * Rule interface — every detection rule implements this.
 *
 * A rule receives a package's metadata and on-disk path, and returns zero or
 * more Findings. Rules are independent: each can be tested in isolation without
 * the scanner or other rules.
 */

import type { Finding } from './finding.js';

export interface PackageMeta {
  name: string;
  version: string;
  /** Absolute path to the package directory. */
  path: string;
  /** Parsed package.json (raw). */
  raw: Record<string, unknown>;
}

export interface RuleContext {
  /** The package-lock.json content if present (for dependency-confusion rule). */
  packageLock?: Record<string, unknown>;
  /** Injected registry fetcher for suspicious-publish rule (tests can stub). */
  fetchRegistryMeta?: (name: string) => Promise<RegistryMeta | null>;
  /** Project root (parent of the scanned node_modules) — where .npmrc lives. */
  projectDir?: string;
}

/**
 * Normalized registry metadata. Note the field is `times` here — the real npm
 * registry returns `time`, and `makeDefaultFetcher` maps it. Test fixtures
 * should use `times`.
 */
export interface RegistryMeta {
  name: string;
  /** ISO timestamps of each version's publish time. */
  times: Record<string, string>;
  /** Maintainer usernames who have published. */
  maintainers: string[];
  /** dist-tags from npm. */
  'dist-tags': Record<string, string>;
}

export interface Rule {
  id: string;
  check(meta: PackageMeta, ctx?: RuleContext): Promise<Finding[]> | Finding[];
}
