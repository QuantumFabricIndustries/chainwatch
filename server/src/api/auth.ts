/**
 * Auth middleware — validates API keys on every request.
 *
 * API key format: cw_<workspace_id>_<random_32_bytes_hex>
 * The server stores bcrypt(key_hash) + sha256(key) — never the raw key.
 * sha256 is an indexed lookup column so auth is O(1); bcrypt still verifies.
 *
 * On validation, sets `request.workspace` to the workspace object and
 * `request.apiKeyId` to the key record id.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import * as bcrypt from 'bcrypt';
import { createHash } from 'node:crypto';
import { getApiKeyBySha256, getWorkspaceById, touchApiKey } from '../db/queries.js';
import type { Workspace } from '../db/queries.js';

declare module 'fastify' {
  interface FastifyRequest {
    workspace?: Workspace;
    apiKeyId?: string;
  }
}

/** Extract the API key from the Authorization header. */
function extractApiKey(req: FastifyRequest): string | null {
  const auth = req.headers['authorization'];
  if (!auth) return null;
  const match = /^Bearer\s+(cw_[a-f0-9-]+_[a-f0-9]+)$/i.exec(auth);
  if (!match) return null;
  return match[1] ?? null;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Validate a raw API key string against the database.
 * Shared by the HTTP middleware and the WebSocket auth path.
 */
export async function validateApiKey(
  rawKey: string,
): Promise<{ workspace: Workspace; apiKeyId: string } | null> {
  // Fast path: indexed sha256 lookup, then constant-time-ish bcrypt verify.
  const keyRow = await getApiKeyBySha256(sha256Hex(rawKey));
  if (keyRow) {
    if (!(await bcrypt.compare(rawKey, keyRow.key_hash))) return null;
    const workspace = await getWorkspaceById(keyRow.workspace_id);
    if (!workspace) return null;
    return { workspace, apiKeyId: keyRow.id };
  }

  // Legacy fallback: keys created before key_sha256 existed. Extract the
  // workspace id from the key format and bcrypt-scan only that workspace's keys.
  const parts = rawKey.split('_');
  if (parts.length < 3) return null;
  const workspace = await getWorkspaceById(parts[1]!);
  if (!workspace) return null;

  const { sql } = await import('../db/index.js');
  const keys = await sql`SELECT * FROM api_keys WHERE workspace_id = ${workspace.id}`;
  for (const row of keys) {
    if (await bcrypt.compare(rawKey, row.key_hash as string)) {
      // Backfill the sha256 so future requests take the fast path.
      sql`UPDATE api_keys SET key_sha256 = ${sha256Hex(rawKey)} WHERE id = ${row.id}`.catch(() => {});
      return { workspace, apiKeyId: row.id as string };
    }
  }
  return null;
}

/**
 * Auth middleware — validates the API key and attaches workspace to the request.
 * Calls done() on success, sends 401 on failure.
 */
export async function authMiddleware(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const rawKey = extractApiKey(req);
  if (!rawKey) {
    await reply.code(401).send({ error: 'Missing or invalid Authorization header. Expected: Bearer cw_<workspace>_<key>' });
    return;
  }

  const result = await validateApiKey(rawKey);
  if (!result) {
    await reply.code(401).send({ error: 'Invalid API key' });
    return;
  }

  req.workspace = result.workspace;
  req.apiKeyId = result.apiKeyId;

  // Update last_used_at (fire and forget).
  touchApiKey(result.apiKeyId).catch(() => {});
}

/**
 * Generate a new API key for a workspace.
 * Returns the raw key (shown to the user once) and stores bcrypt + sha256 hashes.
 */
export async function generateApiKey(workspaceId: string, label: string): Promise<string> {
  const crypto = await import('node:crypto');
  const randomHex = crypto.randomBytes(32).toString('hex');
  const rawKey = `cw_${workspaceId}_${randomHex}`;
  const keyHash = await bcrypt.hash(rawKey, 10);
  await import('../db/queries.js').then((m) =>
    m.createApiKey(workspaceId, keyHash, label, sha256Hex(rawKey)),
  );
  return rawKey;
}

/** Check if a workspace has access to a feature (freemium gate). */
export function hasFeature(workspace: Workspace, feature: 'cloud_sync' | 'dashboard' | 'alerts' | 'team_baseline'): boolean {
  if (workspace.tier === 'enterprise') return true;
  if (workspace.tier === 'team') return true;
  // Free tier: no cloud features.
  return false;
}
