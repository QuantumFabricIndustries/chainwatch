/**
 * Cloud sync client — pushes findings and baselines to the ChainWatch Cloud API.
 *
 * Used by `chainwatch sync`, `scan --sync`, `watch --sync`, and `baseline --sync`.
 *
 * Silently skips if CHAINWATCH_API_KEY is not set (so teams without cloud sync
 * aren't broken by the --sync flag being present).
 */

import type { Finding } from '../scan/finding.js';
import type { BaselineEvent } from '../baseline/types.js';

const DEFAULT_API_URL = 'https://api.chainwatch.dev';
const API_URL = process.env['CHAINWATCH_API_URL'] ?? DEFAULT_API_URL;

export interface SyncOptions {
  apiKey?: string;
  repo?: string;
  apiUrl?: string;
  dryRun?: boolean;
}

/** Get the API key from options or env var. Returns null if not set. */
function getApiKey(opts?: SyncOptions): string | null {
  return opts?.apiKey ?? process.env['CHAINWATCH_API_KEY'] ?? null;
}

/** Detect repo name from git remote origin. */
export async function detectRepoName(): Promise<string | null> {
  try {
    const { execSync } = await import('node:child_process');
    const url = execSync('git remote get-url origin', { encoding: 'utf8', timeout: 5000 }).trim();
    // Parse: git@github.com:org/repo.git → org/repo
    //        https://github.com/org/repo.git → org/repo
    const match = /[:/]([^/]+\/[^/]+?)(?:\.git)?$/.exec(url);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

/** Push findings to the cloud API. */
export async function syncFindings(
  findings: Finding[],
  runId: string,
  opts?: SyncOptions,
): Promise<{ ingested: number; skipped: boolean; error?: string }> {
  const apiKey = getApiKey(opts);
  if (!apiKey) {
    return { ingested: 0, skipped: true };
  }

  const repo = opts?.repo ?? (await detectRepoName());
  if (!repo) {
    return { ingested: 0, skipped: true, error: 'Could not detect repo name. Use --repo to specify.' };
  }

  if (opts?.dryRun) {
    console.log(`[dry-run] Would sync ${findings.length} findings for ${repo} (run: ${runId})`);
    return { ingested: findings.length, skipped: false };
  }

  const apiUrl = opts?.apiUrl ?? API_URL;
  try {
    const res = await fetch(`${apiUrl}/api/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ repo, run_id: runId, findings }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      const body = await res.text();
      return { ingested: 0, skipped: false, error: `API returned ${res.status}: ${body}` };
    }

    const data = await res.json() as { ingested: number; repo_id: string };
    return { ingested: data.ingested, skipped: false };
  } catch (err) {
    return { ingested: 0, skipped: false, error: (err as Error).message };
  }
}

/** Push a baseline file to the cloud API. */
export async function syncBaseline(
  baselinePath: string,
  lockfileHash: string,
  opts?: SyncOptions,
): Promise<{ success: boolean; skipped: boolean; error?: string }> {
  const apiKey = getApiKey(opts);
  if (!apiKey) {
    return { success: false, skipped: true };
  }

  const repo = opts?.repo ?? (await detectRepoName());
  if (!repo) {
    return { success: false, skipped: true, error: 'Could not detect repo name.' };
  }

  const apiUrl = opts?.apiUrl ?? API_URL;
  try {
    const { readFileSync } = await import('node:fs');
    const content = readFileSync(baselinePath);

    const formData = new FormData();
    formData.append('repo', repo);
    formData.append('lockfile_hash', lockfileHash);
    formData.append('file', new Blob([content]), 'baseline.jsonl');

    const res = await fetch(`${apiUrl}/api/v1/baselines`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}` },
      body: formData,
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) {
      const body = await res.text();
      return { success: false, skipped: false, error: `API returned ${res.status}: ${body}` };
    }

    return { success: true, skipped: false };
  } catch (err) {
    return { success: false, skipped: false, error: (err as Error).message };
  }
}

/** Pull a team baseline from the cloud API. */
export async function pullBaseline(
  lockfileHash: string,
  outputPath: string,
  opts?: SyncOptions,
): Promise<{ success: boolean; skipped: boolean; error?: string }> {
  const apiKey = getApiKey(opts);
  if (!apiKey) {
    return { success: false, skipped: true };
  }

  const repo = opts?.repo ?? (await detectRepoName());
  if (!repo) {
    return { success: false, skipped: true, error: 'Could not detect repo name.' };
  }

  const apiUrl = opts?.apiUrl ?? API_URL;
  try {
    const encodedRepo = encodeURIComponent(repo);
    const res = await fetch(
      `${apiUrl}/api/v1/baselines/${encodedRepo}?lockfile_hash=${lockfileHash}`,
      { headers: { 'Authorization': `Bearer ${apiKey}` }, signal: AbortSignal.timeout(15_000) },
    );

    if (!res.ok) {
      const body = await res.text();
      return { success: false, skipped: false, error: `API returned ${res.status}: ${body}` };
    }

    const content = await res.arrayBuffer();
    const { writeFileSync, mkdirSync } = await import('node:fs');
    const { dirname } = await import('node:path');
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, Buffer.from(content));

    return { success: true, skipped: false };
  } catch (err) {
    return { success: false, skipped: false, error: (err as Error).message };
  }
}

/** Compute sha256 hash of a file (for lockfile_hash). */
export async function hashFile(filePath: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  const { readFileSync } = await import('node:fs');
  const content = readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Destroy undici's global dispatcher before process.exit().
 * A fetch()'d keep-alive socket that is mid-close when the process exits hits
 * a libuv UV_HANDLE_CLOSING assert on Windows (exit code 0xC0000409).
 * Call this after the last fetch in any command that hard-exits.
 */
export async function closeNetworkConnections(): Promise<void> {
  try {
    const dispatcher = (globalThis as Record<symbol, unknown>)[
      Symbol.for('undici.globalDispatcher.1')
    ] as { destroy?: () => Promise<void> } | undefined;
    await dispatcher?.destroy?.();
  } catch { /* not an undici env / already closed */ }
}
