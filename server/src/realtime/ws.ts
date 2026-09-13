/**
 * WebSocket server — live event feed for the dashboard.
 *
 * Auth: `?key=cw_...` query param (browsers can't set WS headers) or an
 * `Authorization: Bearer` header for non-browser clients.
 *
 * Channel fan-out: one Redis subscription per workspace channel, with a set
 * of sockets per channel — a client disconnect must NOT unsubscribe the
 * channel while other clients still listen.
 */

import type { FastifyInstance } from 'fastify';
import { redisSub } from './redis.js';
import { validateApiKey } from '../api/auth.js';

interface WsSocket {
  send: (data: string) => void;
  close: (code?: number) => void;
  on: (event: 'close', cb: () => void) => void;
}

/** channel → set of sockets listening on it. */
const channelSockets = new Map<string, Set<WsSocket>>();

let dispatchRegistered = false;

function registerDispatch(): void {
  if (dispatchRegistered) return;
  dispatchRegistered = true;
  redisSub.on('message', (channel: string, message: string) => {
    const sockets = channelSockets.get(channel);
    if (!sockets) return;
    for (const socket of sockets) {
      try {
        socket.send(message);
      } catch { /* socket already closing */ }
    }
  });
}

async function joinChannel(channel: string, socket: WsSocket): Promise<void> {
  registerDispatch();
  let sockets = channelSockets.get(channel);
  if (!sockets) {
    sockets = new Set();
    channelSockets.set(channel, sockets);
    await redisSub.subscribe(channel);
  }
  sockets.add(socket);
}

async function leaveChannel(channel: string, socket: WsSocket): Promise<void> {
  const sockets = channelSockets.get(channel);
  if (!sockets) return;
  sockets.delete(socket);
  if (sockets.size === 0) {
    channelSockets.delete(channel);
    await redisSub.unsubscribe(channel).catch(() => {});
  }
}

export async function registerWebSocketRoutes(app: FastifyInstance): Promise<void> {
  app.get('/ws', { websocket: true }, async (socket: WsSocket, req) => {
    // Query param (browsers) or Authorization header (non-browser clients).
    const queryKey = (req.query as { key?: string }).key;
    const authHeader = req.headers['authorization'];
    const headerKey = /^Bearer\s+(cw_\S+)$/i.exec(authHeader ?? '')?.[1];
    const key = queryKey ?? headerKey;

    if (!key || !key.startsWith('cw_')) {
      socket.send(JSON.stringify({ error: 'Authentication required' }));
      socket.close(4001);
      return;
    }

    const result = await validateApiKey(key);
    if (!result) {
      socket.send(JSON.stringify({ error: 'Invalid API key' }));
      socket.close(4001);
      return;
    }
    const { workspace } = result;

    // Subscribe to the workspace channel (shared subscription — safe for
    // multiple concurrent clients).
    const channel = `chainwatch:workspace:${workspace.id}`;
    await joinChannel(channel, socket);

    socket.on('close', () => {
      leaveChannel(channel, socket).catch(() => {});
    });

    socket.send(JSON.stringify({ event: 'connected', workspace: workspace.name }));
  });
}
