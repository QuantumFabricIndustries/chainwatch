/**
 * Shared host extraction for network interceptors.
 *
 * Node's net/http/dns functions accept a wild variety of argument shapes:
 * strings, URLs, options objects, (port, host) pairs. This normalizes all of
 * them into a bare hostname (lowercase, no port) or '' for IPC/local calls.
 */

type AnyFnArgs = any[];

/** Extract the target host from connect/request/lookup-style arguments. */
export function extractHost(args: AnyFnArgs): string {
  const a = args[0];
  if (!a) return '';
  if (typeof a === 'string') {
    // Unix sockets / Windows named pipes are IPC, not network.
    if (a.startsWith('/') || a.startsWith('\\\\') || a.startsWith('.')) return '';
    try {
      return new URL(a).hostname.toLowerCase();
    } catch {
      // Bare hostname or host:port (dns.lookup('example.com'), net.connect(80, 'h'))
      return stripPort(a.toLowerCase());
    }
  }
  if (a instanceof URL) return a.hostname.toLowerCase();
  if (typeof a === 'object') {
    if (a.socketPath || a.path?.startsWith?.('\\\\')) return '';
    const h = a.hostname || a.host || '';
    return stripPort(String(h).toLowerCase());
  }
  if (typeof a === 'number' && typeof args[1] === 'string') {
    return stripPort(args[1].toLowerCase());
  }
  return '';
}

/** Strip a trailing :port from a host string (options.host may include it). */
function stripPort(host: string): string {
  // IPv6 literal like [::1]:443
  const m = /^(\[[0-9a-f:]+\])(?::\d+)?$/i.exec(host);
  if (m) return m[1]!.slice(1, -1);
  const i = host.lastIndexOf(':');
  return i > 0 && host.indexOf(':') === i ? host.slice(0, i) : host;
}
