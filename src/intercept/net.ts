/**
 * Network interceptor — detects outbound connections to non-allowlisted hosts.
 *
 * Wraps `net`, `http`, `https`, `http2`, `tls`, `dns` (callback + promises),
 * `dgram`, plus the `fetch` and `WebSocket` globals. Any outbound to a host NOT
 * in the policy allowlist fires `network_exfil`. The chain scorer turns this
 * critical when it follows a credential read. Throws on block.
 */

import { createRequire } from 'node:module';
import { ChainWatchBlockError, type Engine } from '../engine.js';
import { extractHost } from './host.js';

const require = createRequire(import.meta.url);
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const tls = require('node:tls');
const dgram = require('node:dgram');
const http2 = require('node:http2');

type AnyFn = (...args: any[]) => any;

interface Restore {
  obj: any;
  name: string;
  fn: AnyFn;
}
const originals: Restore[] = [];

function isAllowlisted(host: string, engine: Engine): boolean {
  if (!host) return true;
  return engine.policy.networkAllowlist.some(
    (allowed) => host === allowed || host.endsWith(`.${allowed}`),
  );
}

function checkHost(host: string, engine: Engine): void {
  if (isAllowlisted(host, engine)) return;
  const { action, event } = engine.evaluate(
    'network_exfil',
    'medium',
    engine.policy.baseScore.network_exfil,
    { host },
  );
  if (action === 'block') throw new ChainWatchBlockError(event);
}

function wrap(obj: any, name: string, engine: Engine): void {
  const original = obj?.[name] as AnyFn | undefined;
  if (typeof original !== 'function') return;
  originals.push({ obj, name, fn: original });
  obj[name] = function patched(...args: any[]): any {
    checkHost(extractHost(args), engine);
    return original.apply(this, args);
  };
}

export function installNet(engine: Engine): void {
  wrap(net, 'connect', engine);
  wrap(net, 'createConnection', engine);
  wrap(tls, 'connect', engine);
  wrap(http, 'request', engine);
  wrap(http, 'get', engine);
  wrap(https, 'request', engine);
  wrap(https, 'get', engine);
  wrap(http2, 'connect', engine);
  wrap(dns, 'lookup', engine);
  wrap(dns, 'resolve', engine);
  wrap(dns, 'resolve4', engine);
  wrap(dns, 'resolve6', engine);
  wrap(dns.promises, 'lookup', engine);
  wrap(dns.promises, 'resolve', engine);
  wrap(dns.promises, 'resolve4', engine);
  wrap(dns.promises, 'resolve6', engine);

  // dgram.send(msg, ..., port, host [, cb]) — UDP/DNS-tunnel exfil channel.
  const dgramSend = dgram.Socket.prototype.send as AnyFn;
  originals.push({ obj: dgram.Socket.prototype, name: 'send', fn: dgramSend });
  dgram.Socket.prototype.send = function patched(...args: any[]): any {
    const host = typeof args[args.length - 2] === 'string'
      ? args[args.length - 2]
      : typeof args[args.length - 1] === 'string'
        ? args[args.length - 1]
        : '';
    checkHost(String(host).toLowerCase(), engine);
    return dgramSend.apply(this, args);
  };

  // Global fetch (undici) — bypasses http.request entirely.
  if (typeof globalThis.fetch === 'function') {
    const origFetch = globalThis.fetch;
    originals.push({ obj: globalThis, name: 'fetch', fn: origFetch as AnyFn });
    globalThis.fetch = function patched(input: any, init?: any): any {
      const host = extractHost([
        typeof input === 'string' || input instanceof URL ? input : input?.url,
      ]);
      checkHost(host, engine);
      return origFetch.apply(this, [input, init]);
    };
  }

  // Global WebSocket — another direct exfil channel.
  if (typeof globalThis.WebSocket === 'function') {
    const OrigWS = globalThis.WebSocket;
    originals.push({ obj: globalThis, name: 'WebSocket', fn: OrigWS as unknown as AnyFn });
    globalThis.WebSocket = function patched(this: any, url: any, protocols?: any) {
      checkHost(extractHost([url]), engine);
      return new (OrigWS as any)(url, protocols);
    } as any;
  }
}

export function uninstallNet(): void {
  for (const { obj, name, fn } of originals.splice(0)) {
    obj[name] = fn;
  }
}
