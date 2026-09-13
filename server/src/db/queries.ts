/**
 * Typed database query functions.
 *
 * Uses postgres.js tagged template literals. No ORM — raw SQL with TypeScript
 * types on the return values.
 */

import { sql } from './index.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  tier: 'free' | 'team' | 'enterprise';
  created_at: Date;
}

export interface ApiKey {
  id: string;
  workspace_id: string;
  key_hash: string;
  /** sha256 of the raw key — indexed lookup column (bcrypt verifies after). */
  key_sha256: string | null;
  label: string | null;
  last_used_at: Date | null;
  created_at: Date;
}

export interface Repo {
  id: string;
  workspace_id: string;
  name: string;
  created_at: Date;
}

export interface FindingRow {
  id: string;
  repo_id: string;
  run_id: string;
  severity: string;
  signal: string;
  package: string;
  description: string;
  file: string | null;
  evidence: string | null;
  chain_score: number | null;
  created_at: Date;
}

export interface BaselineRow {
  id: string;
  repo_id: string;
  lockfile_hash: string;
  content: Buffer;
  run_count: number;
  created_at: Date;
  updated_at: Date;
}

// ─── Workspace queries ──────────────────────────────────────────────────────

export async function createWorkspace(name: string, slug: string, tier: Workspace['tier'] = 'free'): Promise<Workspace> {
  const rows = await sql<Workspace[]>`
    INSERT INTO workspaces (name, slug, tier) VALUES (${name}, ${slug}, ${tier})
    RETURNING *`;
  return rows[0]!;
}

export async function getWorkspaceById(id: string): Promise<Workspace | null> {
  const rows = await sql<Workspace[]>`SELECT * FROM workspaces WHERE id = ${id}`;
  return rows[0] ?? null;
}

export async function getWorkspaceBySlug(slug: string): Promise<Workspace | null> {
  const rows = await sql<Workspace[]>`SELECT * FROM workspaces WHERE slug = ${slug}`;
  return rows[0] ?? null;
}

// ─── API key queries ────────────────────────────────────────────────────────

export async function createApiKey(
  workspaceId: string,
  keyHash: string,
  label: string,
  keySha256?: string,
): Promise<ApiKey> {
  const rows = await sql<ApiKey[]>`
    INSERT INTO api_keys (workspace_id, key_hash, key_sha256, label)
    VALUES (${workspaceId}, ${keyHash}, ${keySha256 ?? null}, ${label})
    RETURNING *`;
  return rows[0]!;
}

/** O(1) key lookup by sha256 digest — replaces the per-key bcrypt table scan. */
export async function getApiKeyBySha256(digest: string): Promise<ApiKey | null> {
  const rows = await sql<ApiKey[]>`SELECT * FROM api_keys WHERE key_sha256 = ${digest}`;
  return rows[0] ?? null;
}

export async function touchApiKey(keyId: string): Promise<void> {
  await sql`UPDATE api_keys SET last_used_at = NOW() WHERE id = ${keyId}`;
}

/** Public-facing key record — never exposes hash material. */
export type ApiKeySummary = Pick<ApiKey, 'id' | 'workspace_id' | 'label' | 'last_used_at' | 'created_at'>;

export async function listApiKeys(workspaceId: string): Promise<ApiKeySummary[]> {
  return sql<ApiKeySummary[]>`SELECT id, workspace_id, label, last_used_at, created_at FROM api_keys WHERE workspace_id = ${workspaceId} ORDER BY created_at DESC`;
}

export async function deleteApiKey(keyId: string, workspaceId: string): Promise<boolean> {
  const rows = await sql`
    DELETE FROM api_keys WHERE id = ${keyId} AND workspace_id = ${workspaceId}
    RETURNING id`;
  return rows.length > 0;
}

// ─── Repo queries ───────────────────────────────────────────────────────────

export async function getOrCreateRepo(workspaceId: string, name: string): Promise<Repo> {
  // Try insert, on conflict return existing.
  const rows = await sql<Repo[]>`
    INSERT INTO repos (workspace_id, name) VALUES (${workspaceId}, ${name})
    ON CONFLICT (workspace_id, name) DO UPDATE SET name = EXCLUDED.name
    RETURNING *`;
  return rows[0]!;
}

export async function listRepos(workspaceId: string): Promise<Repo[]> {
  return sql<Repo[]>`SELECT * FROM repos WHERE workspace_id = ${workspaceId} ORDER BY created_at DESC`;
}

// ─── Finding queries ────────────────────────────────────────────────────────

export async function insertFinding(
  repoId: string,
  runId: string,
  finding: {
    severity: string;
    signal: string;
    package: string;
    description: string;
    file?: string;
    evidence?: string;
    chain_score?: number;
  },
): Promise<FindingRow> {
  const rows = await sql<FindingRow[]>`
    INSERT INTO findings (repo_id, run_id, severity, signal, package, description, file, evidence, chain_score)
    VALUES (${repoId}, ${runId}, ${finding.severity}, ${finding.signal}, ${finding.package}, ${finding.description}, ${finding.file ?? null}, ${finding.evidence ?? null}, ${finding.chain_score ?? null})
    RETURNING *`;
  return rows[0]!;
}

export async function getRecentFindings(workspaceId: string, limit = 20): Promise<(FindingRow & { repo_name: string })[]> {
  return sql<(FindingRow & { repo_name: string })[]>`
    SELECT f.*, r.name as repo_name
    FROM findings f
    JOIN repos r ON f.repo_id = r.id
    WHERE r.workspace_id = ${workspaceId}
    ORDER BY f.created_at DESC
    LIMIT ${limit}`;
}

export async function getFindingsByRepo(repoId: string, limit = 50): Promise<FindingRow[]> {
  return sql<FindingRow[]>`
    SELECT * FROM findings WHERE repo_id = ${repoId} ORDER BY created_at DESC LIMIT ${limit}`;
}

export async function getFindingTrend(workspaceId: string, days = 30): Promise<{ date: string; count: number }[]> {
  return sql<{ date: string; count: number }[]>`
    SELECT DATE(created_at) as date, COUNT(*) as count
    FROM findings f
    JOIN repos r ON f.repo_id = r.id
    WHERE r.workspace_id = ${workspaceId}
      AND f.created_at >= NOW() - ${days} * INTERVAL '1 day'
    GROUP BY DATE(created_at)
    ORDER BY date`;
}

export async function getFindingStats(workspaceId: string): Promise<{
  repos_scanned: number;
  total_findings_7d: number;
  critical_7d: number;
  high_7d: number;
}> {
  const rows = await sql`
    SELECT
      (SELECT COUNT(*) FROM repos WHERE workspace_id = ${workspaceId}) as repos_scanned,
      (SELECT COUNT(*) FROM findings f JOIN repos r ON f.repo_id = r.id WHERE r.workspace_id = ${workspaceId} AND f.created_at >= NOW() - INTERVAL '7 days') as total_findings_7d,
      (SELECT COUNT(*) FROM findings f JOIN repos r ON f.repo_id = r.id WHERE r.workspace_id = ${workspaceId} AND f.severity = 'critical' AND f.created_at >= NOW() - INTERVAL '7 days') as critical_7d,
      (SELECT COUNT(*) FROM findings f JOIN repos r ON f.repo_id = r.id WHERE r.workspace_id = ${workspaceId} AND f.severity = 'high' AND f.created_at >= NOW() - INTERVAL '7 days') as high_7d`;
  return rows[0] as any;
}

// ─── Baseline queries ───────────────────────────────────────────────────────

export async function uploadBaseline(repoId: string, lockfileHash: string, content: Buffer, runCount = 1): Promise<BaselineRow> {
  const rows = await sql<BaselineRow[]>`
    INSERT INTO baselines (repo_id, lockfile_hash, content, run_count)
    VALUES (${repoId}, ${lockfileHash}, ${content}, ${runCount})
    ON CONFLICT (repo_id, lockfile_hash) DO UPDATE
      SET content = EXCLUDED.content, run_count = EXCLUDED.run_count, updated_at = NOW()
    RETURNING *`;
  return rows[0]!;
}

export async function getBaseline(repoId: string, lockfileHash: string): Promise<BaselineRow | null> {
  const rows = await sql<BaselineRow[]>`
    SELECT * FROM baselines WHERE repo_id = ${repoId} AND lockfile_hash = ${lockfileHash}`;
  return rows[0] ?? null;
}

// ─── Alert config queries ───────────────────────────────────────────────────

export interface AlertConfig {
  id: string;
  workspace_id: string;
  type: 'slack' | 'webhook';
  config: { url?: string; channel?: string; secret?: string };
  min_severity: string;
  enabled: boolean;
  created_at: Date;
}

export async function createAlertConfig(
  workspaceId: string,
  type: AlertConfig['type'],
  config: AlertConfig['config'],
  minSeverity: string = 'high',
): Promise<AlertConfig> {
  const rows = await sql<AlertConfig[]>`
    INSERT INTO alert_configs (workspace_id, type, config, min_severity)
    VALUES (${workspaceId}, ${type}, ${JSON.stringify(config)}, ${minSeverity})
    RETURNING *`;
  return rows[0]!;
}

export async function listAlertConfigs(workspaceId: string): Promise<AlertConfig[]> {
  return sql<AlertConfig[]>`SELECT * FROM alert_configs WHERE workspace_id = ${workspaceId} ORDER BY created_at DESC`;
}

export async function getEnabledAlerts(workspaceId: string, severity: string): Promise<AlertConfig[]> {
  const severityRank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
  const minRank = severityRank[severity] ?? 0;
  const rows = await sql<AlertConfig[]>`
    SELECT * FROM alert_configs WHERE workspace_id = ${workspaceId} AND enabled = true`;
  return rows.filter((r) => (severityRank[r.min_severity] ?? 0) <= minRank);
}
