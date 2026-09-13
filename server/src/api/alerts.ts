/**
 * Alerts — Slack + webhook notification dispatch.
 *
 * On CRITICAL/HIGH findings, check alert_configs and dispatch to configured
 * Slack webhooks or custom webhooks.
 */

import type { FindingRow, AlertConfig } from '../db/queries.js';
import { getEnabledAlerts } from '../db/queries.js';
import * as crypto from 'node:crypto';

const SEVERITY_EMOJI: Record<string, string> = {
  critical: '🛑',
  high: '⚠️',
  medium: '🟡',
  low: 'ℹ️',
};

/**
 * SSRF guard — alert/webhook URLs must be public HTTPS endpoints.
 * Blocks localhost, RFC-1918/loopback/link-local, and cloud metadata hosts.
 */
export function assertUrlAllowed(rawUrl: string): void {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('Webhook URL must be http(s)');
  }
  const host = url.hostname.toLowerCase();
  const blocked =
    host === 'localhost' ||
    host === 'metadata.google.internal' ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^0\./.test(host) ||
    host === '::1' ||
    host === '[::1]' ||
    host.endsWith('.internal') ||
    host.endsWith('.local');
  if (blocked) {
    throw new Error(`Webhook URL host "${host}" is not allowed (private/internal address)`);
  }
}

/**
 * Check alerts for a batch of findings and dispatch to configured channels.
 * Called fire-and-forget from the events handler.
 */
export async function checkAlerts(workspaceId: string, findings: FindingRow[]): Promise<void> {
  if (findings.length === 0) return;

  // Get the highest severity finding to check against alert thresholds.
  const severityRank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
  const maxSeverity = findings.reduce((max, f) => Math.max(max, severityRank[f.severity] ?? 0), 0);
  const severityName = Object.entries(severityRank).find(([, v]) => v === maxSeverity)?.[0] ?? 'low';

  const alerts = await getEnabledAlerts(workspaceId, severityName);
  if (alerts.length === 0) return;

  for (const alert of alerts) {
    try {
      if (alert.type === 'slack') {
        await sendSlackAlert(alert, findings);
      } else if (alert.type === 'webhook') {
        await sendWebhookAlert(alert, findings);
      }
    } catch (err) {
      console.error(`[alerts] Failed to dispatch ${alert.type} alert:`, err);
    }
  }
}

/** Send a Slack alert via incoming webhook. */
async function sendSlackAlert(alert: AlertConfig, findings: FindingRow[]): Promise<void> {
  const url = alert.config.url;
  if (!url) return;
  assertUrlAllowed(url);

  const blocks = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `ChainWatch: ${findings.length} new finding(s)` },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: findings.slice(0, 5).map((f) =>
          `${SEVERITY_EMOJI[f.severity] ?? '⚠'} *${f.severity.toUpperCase()}* — ${f.signal} in \`${f.package}\`\n${f.description}`
        ).join('\n\n'),
      },
    },
  ];

  if (findings.length > 5) {
    blocks.push({
      type: 'context',
      text: { type: 'mrkdwn', text: `... and ${findings.length - 5} more` },
    } as any);
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ blocks }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    throw new Error(`Slack webhook returned ${res.status}: ${await res.text()}`);
  }
}

/** Send a webhook alert with HMAC signing. */
async function sendWebhookAlert(alert: AlertConfig, findings: FindingRow[]): Promise<void> {
  const url = alert.config.url;
  const secret = alert.config.secret;
  if (!url) return;
  assertUrlAllowed(url);

  const payload = JSON.stringify({
    event: 'chainwatch.findings',
    timestamp: new Date().toISOString(),
    findings: findings.map((f) => ({
      severity: f.severity,
      signal: f.signal,
      package: f.package,
      description: f.description,
      file: f.file,
    })),
  });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  if (secret) {
    const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    headers['X-ChainWatch-Signature'] = `sha256=${signature}`;
  }

  const res = await fetch(url, { method: 'POST', headers, body: payload, signal: AbortSignal.timeout(10_000) });
  if (!res.ok) {
    throw new Error(`Webhook returned ${res.status}: ${await res.text()}`);
  }
}

/** Test an alert config (used by POST /api/v1/alerts/test). */
export async function testAlert(alert: AlertConfig): Promise<{ success: boolean; message: string }> {
  const testFinding: FindingRow = {
    id: 'test',
    repo_id: 'test',
    run_id: 'test',
    severity: 'critical',
    signal: 'CW003',
    package: 'test-pkg@1.0.0',
    description: 'Test alert from ChainWatch — this is a verification message.',
    file: null,
    evidence: null,
    chain_score: null,
    created_at: new Date(),
  };

  try {
    if (alert.type === 'slack') {
      await sendSlackAlert(alert, [testFinding]);
    } else {
      await sendWebhookAlert(alert, [testFinding]);
    }
    return { success: true, message: 'Alert sent successfully' };
  } catch (err) {
    return { success: false, message: (err as Error).message };
  }
}
