/**
 * Rules barrel — exports all detection rules.
 * New rules are added here and automatically picked up by the scanner.
 */

import { postinstallNetwork } from './postinstall-network.js';
import { postinstallShell } from './postinstall-shell.js';
import { credentialFileAccess } from './credential-file-access.js';
import { obfuscationScore } from './obfuscation-score.js';
import { suspiciousPublish } from './suspicious-publish.js';
import { dependencyConfusion } from './dependency-confusion.js';
import { hostageToken } from './hostage-token.js';
import type { Rule } from '../types.js';

export const ALL_RULES: Rule[] = [
  postinstallNetwork,
  postinstallShell,
  credentialFileAccess,
  obfuscationScore,
  suspiciousPublish,
  dependencyConfusion,
  hostageToken,
];

export {
  postinstallNetwork,
  postinstallShell,
  credentialFileAccess,
  obfuscationScore,
  suspiciousPublish,
  dependencyConfusion,
  hostageToken,
};
