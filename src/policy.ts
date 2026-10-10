/**
 * Default policy — what ChainWatch considers suspicious and what it does about it.
 *
 * The policy is deliberately permissive on individual signals (a package reading
 * a file or making a network call is usually fine) and strict on *chains*. The
 * chain scorer is where the real decisions happen.
 */

import type { Action, Severity, SignalType } from './events.js';

export interface Policy {
  /** Per-signal base severity before chain context. */
  baseSeverity: Record<SignalType, Severity>;
  /** Per-signal base score (0–100) before chain context. */
  baseScore: Record<SignalType, number>;
  /** When a single event's score crosses this, it's flagged. */
  flagThreshold: number;
  /** When a single event's score crosses this, it's blocked. */
  blockThreshold: number;
  /** When the chain score crosses this, the whole chain is blocked. */
  chainBlockThreshold: number;
  /** Hosts that are always allowed (npm registry, common CDNs). */
  networkAllowlist: string[];
  /** Credential file patterns. A read of any of these by a non-declared package
   *  fires `credential_access`. */
  credentialPatterns: RegExp[];
  /** Packages explicitly trusted (skip attribution-based flagging). */
  trustedPackages: string[];
}

export const DEFAULT_POLICY: Policy = {
  baseSeverity: {
    credential_access: 'high',
    network_exfil: 'medium',
    self_propagation: 'critical',
    install_script: 'high',
    shell_spawn: 'medium',
  },
  baseScore: {
    credential_access: 60,
    network_exfil: 30,
    self_propagation: 70,
    install_script: 50,
    shell_spawn: 40,
  },
  flagThreshold: 50,
  blockThreshold: 80,
  chainBlockThreshold: 75,
  networkAllowlist: [
    'registry.npmjs.org',
    'registry.yarnpkg.com',
    'nodejs.org',
    // NOTE: github.com is deliberately NOT allowlisted — Shai-Hulud exfiltrated
    // stolen tokens to attacker-controlled GitHub repos. A lone github.com call
    // only logs (score 30 < flagThreshold); it escalates only when chained with
    // credential access, which is exactly the worm pattern.
  ],
  credentialPatterns: [
    /(?:^|[\\/])\.npmrc$/i,
    /[\\/]\.ssh[\\/]/i,
    /(?:^|[\\/])\.env(?:\.[a-z]+)?$/i,
    /[\\/]\.aws[\\/]credentials/i,
    /[\\/]\.aws[\\/]config/i,
    /[\\/]\.config[\\/]gcloud/i,
    /[\\/]\.kube[\\/]config/i,
    /[\\/]\.docker[\\/]config\.json$/i,
    /(?:^|[\\/])\.git-credentials$/i,
    /(?:^|[\\/])\.netrc$/i,
    /(?:^|[\\/])\.pypirc$/i,
    // gh CLI's stored GitHub token — the tensorlake worm's main target.
    /[\\/](?:\.config[\\/]gh|GitHub CLI)[\\/]hosts\.yml$/i,
  ],
  trustedPackages: [],
};
