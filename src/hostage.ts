/**
 * Host check for the tensorlake-style "hostage token" monitor.
 *
 * The worm leaves a background job that re-checks a stolen GitHub token every
 * minute for 24h and deletes the home directory once the token is rejected.
 * This module finds that job's footprint and the repo files the worm commits
 * to re-run itself, and spells out the order to clean up in: monitor first,
 * revoke second.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

export interface HostageArtifact {
  /** monitor = will wipe on revoke; repo = re-runs the worm when the project opens. */
  kind: 'monitor' | 'repo';
  path: string;
  detail: string;
}

export interface HostageCheckOptions {
  home?: string;
  platform?: NodeJS.Platform;
  projectDir?: string;
  /** Lists scheduled tasks on Windows (CSV text). Injected by tests. */
  listScheduledTasks?: () => string;
}

const MONITOR_FILES: Record<string, string[]> = {
  linux: [
    '.config/gh-token-monitor',
    '.local/bin/gh-token-monitor.sh',
    '.config/systemd/user/gh-token-monitor.service',
  ],
  darwin: [
    '.config/gh-token-monitor',
    '.local/bin/gh-token-monitor.sh',
    'Library/LaunchAgents/com.user.gh-token-monitor.plist',
  ],
  win32: ['.config/gh-token-monitor'],
};

const REPO_IOC_RE = /gh-token-monitor|iseekaigogo\.com|Math_Symbol|Shai-Hulud/i;

function defaultListScheduledTasks(): string {
  try {
    return execFileSync('schtasks', ['/query', '/fo', 'csv', '/v'], { encoding: 'utf8', timeout: 15000 });
  } catch {
    return '';
  }
}

export function checkHost(opts: HostageCheckOptions = {}): HostageArtifact[] {
  const home = opts.home ?? os.homedir();
  const platform = opts.platform ?? process.platform;
  const projectDir = opts.projectDir ?? process.cwd();
  const found: HostageArtifact[] = [];

  for (const rel of MONITOR_FILES[platform] ?? MONITOR_FILES.linux!) {
    const p = path.join(home, rel);
    if (fs.existsSync(p)) {
      found.push({ kind: 'monitor', path: p, detail: 'gh-token-monitor file' });
    }
  }

  if (platform === 'win32') {
    const tasks = (opts.listScheduledTasks ?? defaultListScheduledTasks)();
    for (const line of tasks.split(/\r?\n/)) {
      if (/monitor\.ps1|gh-token-monitor/i.test(line)) {
        const name = line.split('","')[1] ?? line.slice(0, 80);
        found.push({ kind: 'monitor', path: `Task Scheduler: ${name}`, detail: 'logon task running monitor.ps1' });
      }
    }
  }

  for (const rel of ['.claude/settings.json', '.vscode/tasks.json']) {
    const p = path.join(projectDir, rel);
    let content = '';
    try {
      content = fs.readFileSync(p, 'utf8');
    } catch {
      continue;
    }
    if (REPO_IOC_RE.test(content)) {
      found.push({ kind: 'repo', path: p, detail: 'contains worm indicator — re-runs the payload when the project opens' });
    } else if (rel.endsWith('tasks.json') && /"runOn"\s*:\s*"folderOpen"/.test(content)) {
      found.push({ kind: 'repo', path: p, detail: 'task auto-runs on folder open — confirm you added it' });
    }
  }

  return found;
}

/** Cleanup steps for the platform, in the only safe order. */
export function remediationSteps(platform: NodeJS.Platform = process.platform): string[] {
  const kill =
    platform === 'darwin'
      ? 'launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.user.gh-token-monitor.plist\n' +
        '     rm -rf ~/.config/gh-token-monitor ~/.local/bin/gh-token-monitor.sh ~/Library/LaunchAgents/com.user.gh-token-monitor.plist'
      : platform === 'win32'
        ? 'Open Task Scheduler, delete the logon task that runs monitor.ps1, then delete %USERPROFILE%\\.config\\gh-token-monitor'
        : 'systemctl --user disable --now gh-token-monitor.service\n' +
          '     rm -rf ~/.config/gh-token-monitor ~/.local/bin/gh-token-monitor.sh ~/.config/systemd/user/gh-token-monitor.service';
  return [
    'Do NOT revoke any GitHub token yet — the monitor wipes your home directory when the token stops working.',
    'Back up anything you cannot lose.',
    `Stop and delete the monitor:\n     ${kill}`,
    'Remove the package: delete node_modules, pin a clean version, run `npm cache clean --force`, set ignore-scripts=true in .npmrc.',
    'Run `chainwatch hostage-check` again and confirm it is clean.',
    'Now revoke the GitHub token, then rotate npm, cloud, SSH and AI-tool keys.',
    'Check your repos for commits by claude@users.noreply.github.com and unexpected .claude/ or .vscode/ files.',
  ];
}
