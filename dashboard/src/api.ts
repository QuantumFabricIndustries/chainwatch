/**
 * API client for the ChainWatch dashboard.
 * Reads the API key from localStorage and makes authenticated requests.
 */

export interface Finding {
  id: string;
  repo_id: string;
  repo_name?: string;
  run_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  signal: string;
  package: string;
  description: string;
  file: string | null;
  evidence: string | null;
  chain_score: number | null;
  created_at: string;
}

export interface OverviewData {
  workspace: { name: string; tier: string };
  stats: {
    repos_scanned: number;
    total_findings_7d: number;
    critical_7d: number;
    high_7d: number;
  };
  recent_findings: Finding[];
  trend: { date: string; count: number }[];
}

export interface Repo {
  id: string;
  workspace_id: string;
  name: string;
  created_at: string;
}

const API_BASE = '/api/v1';

export function getApiKey(): string | null {
  return localStorage.getItem('chainwatch_api_key');
}

export function setApiKey(key: string): void {
  localStorage.setItem('chainwatch_api_key', key);
}

export function clearApiKey(): void {
  localStorage.removeItem('chainwatch_api_key');
}

function authHeaders(): Record<string, string> {
  const key = getApiKey();
  return key ? { Authorization: `Bearer ${key}` } : {};
}

async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

async function apiDelete<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { method: 'DELETE', headers: authHeaders() });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

export interface ApiKeyInfo {
  id: string;
  label: string | null;
  last_used_at: string | null;
  created_at: string;
}

export const api = {
  getOverview: () => apiGet<OverviewData>('/dashboard/overview'),
  getRepos: () => apiGet<{ repos: Repo[] }>('/dashboard/repos'),
  getRepoDetail: (id: string) => apiGet<{ repo: Repo; findings: Finding[]; signal_breakdown: { signal: string; count: number }[] }>(`/dashboard/repos/${id}`),
  getAlerts: () => apiGet<{ alerts: any[] }>('/alerts'),
  createAlert: (type: string, config: object, minSeverity?: string) =>
    apiPost<{ alert: any }>('/alerts', { type, config, min_severity: minSeverity }),
  testAlert: (type: string, config: object) =>
    apiPost<{ success: boolean; message: string }>('/alerts/test', { type, config }),
  getApiKeys: () => apiGet<{ keys: ApiKeyInfo[] }>('/api-keys'),
  createApiKey: (label: string) => apiPost<{ api_key: string }>('/api-keys', { label }),
  deleteApiKey: (id: string) => apiDelete<{ deleted: boolean }>(`/api-keys/${id}`),
};

/** Create a WebSocket connection for the live event feed. */
export function createEventSocket(onMessage: (finding: Finding) => void): WebSocket {
  const key = getApiKey();
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws?key=${key}`);
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.event !== 'connected') {
        onMessage(data as Finding);
      }
    } catch { /* ignore */ }
  };
  return ws;
}
