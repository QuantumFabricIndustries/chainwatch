/**
 * Baseline recorder — captures ALL behavioral events from core modules during
 * a watch session, for building a known-good baseline.
 *
 * Unlike the Phase 1 interceptor (which only emits events for SUSPICIOUS
 * actions), the recorder captures every fs_read, network_out, child_process,
 * and dns_lookup — normalized and aggregated by (pkg, signal, detail).
 *
 * It installs its own lightweight wrappers alongside the Phase 1 interceptors.
 * The wrappers record behavior and call through to the original functions.
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import * as os from 'node:os';

import { attributeCall } from '../attribution.js';
import { PackageResolver } from '../resolver.js';
import { normalizeDetail } from './store.js';
import { injectWorkerPreload, unpatchWorker } from '../intercept/worker.js';
import { extractHost } from '../intercept/host.js';
import type { BaselineEvent, BaselineSignal } from './types.js';

const require = createRequire(import.meta.url);

type AnyFn = (...args: any[]) => any;

interface RecordedEntry {
  pkg: string;
  signal: BaselineSignal;
  detail: string;
  count: number;
}

export class BaselineRecorder {
  private readonly resolver: PackageResolver;
  private readonly entries = new Map<string, RecordedEntry>();
  private readonly originals: Record<string, AnyFn> = {};
  private installed = false;
  private readonly runTimestamp: string;

  constructor() {
    this.resolver = new PackageResolver();
    this.runTimestamp = new Date().toISOString();
  }

  /** Install wrappers on core modules. Call before running the watched command. */
  install(): void {
    if (this.installed) return;
    this.installed = true;
    // Wire the module-level reference so the wrappers can reach this recorder —
    // without this, record() silently no-ops when install() is called directly
    // instead of via startRecording().
    recorder = this;
    this.resolver.scan();
    this.wrapFs();
    this.wrapNet();
    this.wrapChildProcess();
    // Workers get a fresh module registry — inject the recorder preload into
    // their execArgv so recording covers them too.
    injectWorkerPreload();
  }

  /** Remove wrappers, restore originals. */
  uninstall(): void {
    if (!this.installed) return;
    this.installed = false;
    if (recorder === this) recorder = null;
    unpatchWorker();
    for (const [key, fn] of Object.entries(this.originals)) {
      const [modName, fnName] = key.split('.');
      if (!fnName) continue;
      this.getModule(modName ?? '')[fnName] = fn;
      delete this.originals[key];
    }
  }

  /** Get all recorded events as BaselineEvent[]. */
  getEvents(tag?: string): BaselineEvent[] {
    return [...this.entries.values()].map((e) => ({
      pkg: e.pkg,
      signal: e.signal,
      detail: e.detail,
      count: e.count,
      run: this.runTimestamp,
      ...(tag ? { tag } : {}),
    }));
  }

  /** Number of unique (pkg, signal, detail) entries recorded. */
  get eventCount(): number {
    return this.entries.size;
  }

  /** Number of unique packages observed. */
  get packageCount(): number {
    return new Set([...this.entries.values()].map((e) => e.pkg)).size;
  }

  // ─── Wrappers ─────────────────────────────────────────────────────────────

  private record(signal: BaselineSignal, detail: string): void {
    const attr = attributeCall(this.resolver);
    // Skip ChainWatch itself and entry-point frames.
    if (attr.package === '<entry>' || attr.package === '<unknown>') return;
    if (attr.package === 'chainwatch') return;

    const normalized = normalizeDetail(signal, detail);
    const key = `${attr.package}\x00${signal}\x00${normalized}`;
    const existing = this.entries.get(key);
    if (existing) {
      existing.count++;
    } else {
      this.entries.set(key, {
        pkg: attr.package,
        signal,
        detail: normalized,
        count: 1,
      });
    }
  }

  private wrapFs(): void {
    const fs = require('node:fs');
    const wrap = (name: string, signal: BaselineSignal, extractPath: (args: any[]) => string) => {
      const original = fs[name] as AnyFn;
      this.originals[`fs.${name}`] = original;
      fs[name] = function patched(...args: any[]): any {
        const p = extractPath(args);
        if (p) recorder?.record(signal, p);
        return original.apply(this, args);
      };
    };

    // Read functions → fs_read
    wrap('readFileSync', 'fs_read', (a) => String(a[0] ?? ''));
    wrap('readFile', 'fs_read', (a) => String(a[0] ?? ''));
    wrap('createReadStream', 'fs_read', (a) => String(a[0] ?? ''));
    // Write functions → fs_write
    wrap('writeFileSync', 'fs_write', (a) => String(a[0] ?? ''));
    wrap('writeFile', 'fs_write', (a) => String(a[0] ?? ''));
  }

  private wrapNet(): void {
    const http = require('node:http');
    const https = require('node:https');
    const dns = require('node:dns');
    const net = require('node:net');

    const wrapRequest = (mod: any, modName: string, name: string) => {
      const original = mod[name] as AnyFn;
      this.originals[`${modName}.${name}`] = original;
      mod[name] = function patched(...args: any[]): any {
        const host = extractHost(args);
        if (host) recorder?.record('network_out', host);
        return original.apply(this, args);
      };
    };

    wrapRequest(http, 'http', 'request');
    wrapRequest(http, 'http', 'get');
    wrapRequest(https, 'https', 'request');
    wrapRequest(https, 'https', 'get');

    // net.connect
    const netConnect = net.connect as AnyFn;
    this.originals['net.connect'] = netConnect;
    net.connect = function patched(...args: any[]): any {
      const host = extractHost(args);
      if (host) recorder?.record('network_out', host);
      return netConnect.apply(this, args);
    };

    // dns.lookup → dns_lookup
    const wrapDns = (name: string) => {
      const original = dns[name] as AnyFn;
      this.originals[`dns.${name}`] = original;
      dns[name] = function patched(...args: any[]): any {
        const host = String(args[0] ?? '');
        if (host) recorder?.record('dns_lookup', host);
        return original.apply(this, args);
      };
    };
    wrapDns('lookup');
    wrapDns('resolve');
    wrapDns('resolve4');
    wrapDns('resolve6');
  }

  private wrapChildProcess(): void {
    const cp = require('node:child_process');
    const wrap = (name: string) => {
      const original = cp[name] as AnyFn;
      this.originals[`cp.${name}`] = original;
      cp[name] = function patched(...args: any[]): any {
        const cmd = String(args[0] ?? '');
        if (cmd) recorder?.record('child_process', cmd);
        return original.apply(this, args);
      };
    };
    wrap('exec');
    wrap('execSync');
    wrap('spawn');
    wrap('spawnSync');
    wrap('fork');
  }

  private getModule(name: string): any {
    switch (name) {
      case 'fs': return require('node:fs');
      case 'http': return require('node:http');
      case 'https': return require('node:https');
      case 'dns': return require('node:dns');
      case 'net': return require('node:net');
      case 'cp': return require('node:child_process');
      default: return {};
    }
  }
}

// Module-level recorder reference so wrappers can access it.
// This is set by install() and cleared by uninstall().
let recorder: BaselineRecorder | null = null;

/**
 * Factory + installer: creates a recorder, installs it, and returns it.
 * The recorder auto-uninstalls if the process exits.
 */
export function startRecording(): BaselineRecorder {
  const rec = new BaselineRecorder();
  recorder = rec;
  rec.install();
  return rec;
}

/** Stop recording and return the recorder for event extraction. */
export function stopRecording(rec: BaselineRecorder): BaselineRecorder {
  rec.uninstall();
  recorder = null;
  return rec;
}


