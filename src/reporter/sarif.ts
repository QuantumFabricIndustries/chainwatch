/**
 * SARIF reporter — Static Analysis Results Interchange Format.
 *
 * Maps ChainWatch findings to the SARIF v2.1.0 schema so results show in the
 * GitHub Security tab (used by the Phase 4 GitHub Action).
 *
 * Rule IDs:
 *   CW001 — PostinstallNetwork
 *   CW002 — PostinstallShell
 *   CW003 — CredentialFileAccess
 *   CW004 — ObfuscationScore
 *   CW005 — SuspiciousPublish
 *   CW006 — DependencyConfusion
 *   CW007 — BehavioralDrift
 *   CW008 — HostageToken
 */

import type { Finding, Severity } from '../scan/finding.js';
import { CW_VERSION } from '../version.js';

const SARIF_LEVEL: Record<Severity, 'note' | 'warning' | 'error'> = {
  low: 'note',
  medium: 'warning',
  high: 'error',
  critical: 'error',
};

/** Map ChainWatch rule names to stable SARIF rule IDs. */
const RULE_ID_MAP: Record<string, string> = {
  postinstall_network: 'CW001',
  postinstall_shell: 'CW002',
  credential_file_access: 'CW003',
  obfuscation_score: 'CW004',
  suspicious_publish: 'CW005',
  dependency_confusion: 'CW006',
  behavioral_drift: 'CW007',
  hostage_token: 'CW008',
};

/** Full rule metadata for the SARIF tool driver. */
const RULE_METADATA: Record<string, { name: string; description: string }> = {
  CW001: { name: 'PostinstallNetwork', description: 'Postinstall script makes network request' },
  CW002: { name: 'PostinstallShell', description: 'Postinstall script spawns shell or publishes to npm' },
  CW003: { name: 'CredentialFileAccess', description: 'Package accesses credential files' },
  CW004: { name: 'ObfuscationScore', description: 'Package source contains suspicious obfuscation' },
  CW005: { name: 'SuspiciousPublish', description: 'Package version published recently by new maintainer' },
  CW006: { name: 'DependencyConfusion', description: 'Scoped package resolved from public registry' },
  CW007: { name: 'BehavioralDrift', description: 'Package behavior deviates from recorded baseline' },
  CW008: { name: 'HostageToken', description: 'Token-stealing worm with wipe-on-revoke monitor (remove before revoking)' },
};

/** All known rule IDs (for the rules array even when no findings reference them). */
const ALL_RULE_IDS = Object.keys(RULE_METADATA);

export interface SarifReport {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: 'note' | 'warning' | 'error' };
}

interface SarifResult {
  ruleId: string;
  level: 'note' | 'warning' | 'error';
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: { primaryLocationLineHash: string };
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId?: string };
    region?: { startLine: number };
  };
}

/** Get the SARIF rule ID for a ChainWatch rule name. */
export function getRuleId(ruleName: string): string {
  return RULE_ID_MAP[ruleName] ?? ruleName;
}

/** Get the default SARIF level for a rule ID. */
function getDefaultLevel(ruleId: string): 'note' | 'warning' | 'error' {
  // CW004 (obfuscation) and CW005 (suspicious publish) and CW007 (drift) are warnings by default.
  // Everything else is error.
  if (ruleId === 'CW004' || ruleId === 'CW005' || ruleId === 'CW007') return 'warning';
  return 'error';
}

/** Generate a SARIF report object from findings. */
export function generateSarifObject(findings: Finding[], toolVersion = CW_VERSION): SarifReport {
  const rules = buildRules(findings);
  const results: SarifResult[] = findings.map(toSarifResult);

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ChainWatch',
            version: toolVersion,
            informationUri: 'https://github.com/quantum-fabric-industries/chainwatch',
            rules,
          },
        },
        results,
      },
    ],
  };
}

/** Generate a SARIF report as a JSON string. */
export function formatSarif(findings: Finding[], toolVersion = CW_VERSION): string {
  return JSON.stringify(generateSarifObject(findings, toolVersion), null, 2);
}

// Keep backward compat with Phase 2 callers that imported formatSarif.
export { formatSarif as generateSarif };

function buildRules(findings: Finding[]): SarifRule[] {
  // Collect rule IDs referenced by findings.
  const referencedIds = new Set(findings.map((f) => getRuleId(f.rule)));

  // Include all known rules, plus any unknown ones from findings.
  const allIds = new Set([...ALL_RULE_IDS, ...referencedIds]);

  return [...allIds].map((id) => {
    const meta = RULE_METADATA[id];
    if (meta) {
      return {
        id,
        name: meta.name,
        shortDescription: { text: meta.description },
        helpUri: `https://chainwatch.dev/rules/${id}`,
        defaultConfiguration: { level: getDefaultLevel(id) },
      };
    }
    // Unknown rule — use the ID as the name.
    return {
      id,
      name: id,
      shortDescription: { text: id },
      defaultConfiguration: { level: 'warning' },
    };
  });
}

/** "@scope/name@1.2.3" → "@scope/name". */
function packageName(ref: string): string {
  const at = ref.lastIndexOf('@');
  return at > 0 ? ref.slice(0, at) : ref;
}

function toSarifResult(f: Finding): SarifResult {
  const ruleId = getRuleId(f.rule);
  const file = f.file ?? '';
  // Split on the LAST colon so Windows paths (C:\...) and rel paths with
  // backslashes don't corrupt the URI. Normalize to forward slashes — SARIF
  // URIs are slash-separated.
  const colon = file.lastIndexOf(':');
  const hasLine = colon > 0 && /^\d+$/.test(file.slice(colon + 1));
  // Code scanning rejects a result with no artifact location, so package-level
  // findings (typosquat, known-bad version) point at the package's manifest.
  const uri = file
    ? (hasLine ? file.slice(0, colon) : file).replace(/\\/g, '/')
    : `node_modules/${packageName(f.package)}/package.json`;
  const startLine = hasLine ? parseInt(file.slice(colon + 1), 10) : undefined;

  return {
    ruleId,
    level: SARIF_LEVEL[f.severity],
    message: { text: f.description },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
          ...(startLine ? { region: { startLine } } : {}),
        },
      },
    ],
  };
}
