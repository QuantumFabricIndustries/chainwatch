/**
 * ChainWatch configuration — `chainwatch.config.json` in the project root.
 *
 * Optional file. Everything has a default; the file overrides:
 *
 *   {
 *     "trustedPackages": ["esbuild", "my-internal-tool"],
 *     "networkAllowlist": ["npm.corp.example.com"],
 *     "credentialPatterns": ["\\\\.pem$", "id_ed25519"],
 *     "blockOn": "high",
 *     "flagThreshold": 50,
 *     "blockThreshold": 80,
 *     "chainBlockThreshold": 75
 *   }
 *
 * Env vars (set by `chainwatch watch` flags) take precedence over the file.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { DEFAULT_POLICY, type Policy } from './policy.js';
import type { Severity } from './events.js';

export interface ChainWatchConfig {
  trustedPackages?: string[];
  networkAllowlist?: string[];
  /** Extra regex strings for credential file paths. */
  credentialPatterns?: string[];
  /** Severity at which single events block: low|medium|high|critical. */
  blockOn?: Severity;
  flagThreshold?: number;
  blockThreshold?: number;
  chainBlockThreshold?: number;
}

const CONFIG_FILES = ['chainwatch.config.json', '.chainwatchrc.json'];

/** Severity → score threshold mapping for --block-on / blockOn. */
const BLOCK_SCORE: Record<Severity, number> = {
  low: 1,
  medium: 30,
  high: 50,
  critical: 70,
};

/** Find and parse the config file. Returns {} when absent or invalid. */
export function loadConfig(cwd: string = process.cwd()): ChainWatchConfig {
  for (const name of CONFIG_FILES) {
    const file = path.join(cwd, name);
    try {
      if (!fs.existsSync(file)) continue;
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as ChainWatchConfig;
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      // Invalid config file — fall through to defaults.
    }
  }
  return {};
}

/**
 * Build the effective Policy: defaults ← config file ← env vars.
 * Env vars used (set by `chainwatch watch` CLI flags):
 *   CHAINWATCH_BLOCK_ON     low|medium|high|critical
 *   CHAINWATCH_TRUSTED      comma-separated package names
 *   CHAINWATCH_ALLOW_HOSTS  comma-separated extra allowlist hosts
 */
export function buildPolicy(cwd: string = process.cwd()): Policy {
  const cfg = loadConfig(cwd);
  const policy: Policy = {
    ...DEFAULT_POLICY,
    networkAllowlist: [...DEFAULT_POLICY.networkAllowlist],
    credentialPatterns: [...DEFAULT_POLICY.credentialPatterns],
    trustedPackages: [...DEFAULT_POLICY.trustedPackages],
    baseSeverity: { ...DEFAULT_POLICY.baseSeverity },
    baseScore: { ...DEFAULT_POLICY.baseScore },
  };

  if (cfg.trustedPackages) policy.trustedPackages.push(...cfg.trustedPackages);
  if (cfg.networkAllowlist) {
    policy.networkAllowlist.push(...cfg.networkAllowlist.map((h) => h.toLowerCase()));
  }
  if (cfg.credentialPatterns) {
    for (const p of cfg.credentialPatterns) {
      try {
        policy.credentialPatterns.push(new RegExp(p, 'i'));
      } catch { /* skip invalid pattern */ }
    }
  }
  if (cfg.flagThreshold) policy.flagThreshold = cfg.flagThreshold;
  if (cfg.blockThreshold) policy.blockThreshold = cfg.blockThreshold;
  if (cfg.chainBlockThreshold) policy.chainBlockThreshold = cfg.chainBlockThreshold;

  const blockOn = (process.env['CHAINWATCH_BLOCK_ON'] ?? cfg.blockOn)?.toLowerCase() as
    | Severity
    | undefined;
  if (blockOn && blockOn in BLOCK_SCORE) {
    policy.blockThreshold = Math.min(policy.blockThreshold, BLOCK_SCORE[blockOn]);
    policy.chainBlockThreshold = Math.min(policy.chainBlockThreshold, BLOCK_SCORE[blockOn]);
  }

  const trusted = process.env['CHAINWATCH_TRUSTED'];
  if (trusted) policy.trustedPackages.push(...trusted.split(',').map((s) => s.trim()).filter(Boolean));

  const hosts = process.env['CHAINWATCH_ALLOW_HOSTS'];
  if (hosts) {
    policy.networkAllowlist.push(
      ...hosts.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
    );
  }

  return policy;
}
