import { useEffect, useState, useRef } from 'react';
import { createEventSocket, type Finding } from '../api.js';
import FindingCard from '../components/FindingCard.js';

export default function EventFeed() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState<'all' | 'critical' | 'high'>('all');
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempts = 0;
    let unmounted = false;

    const connect = () => {
      if (unmounted) return;
      ws = createEventSocket((finding) => {
        setFindings((prev) => [finding, ...prev].slice(0, 100));
      });
      wsRef.current = ws;
      ws.onopen = () => { attempts = 0; setConnected(true); };
      ws.onclose = () => {
        setConnected(false);
        if (unmounted) return;
        // Exponential backoff: 1s, 2s, 4s, ... capped at 30s.
        const delay = Math.min(1000 * 2 ** attempts, 30_000);
        attempts += 1;
        reconnectTimer = setTimeout(connect, delay);
      };
      ws.onerror = () => ws?.close(); // let onclose schedule the reconnect
    };
    connect();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      // Prevent the close handler from scheduling a reconnect after unmount.
      if (ws) ws.onclose = null;
      ws?.close();
    };
  }, []);

  const filtered = findings.filter((f) => {
    if (filter === 'all') return true;
    if (filter === 'critical') return f.severity === 'critical';
    if (filter === 'high') return f.severity === 'critical' || f.severity === 'high';
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Live Event Feed</h1>
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 text-sm ${connected ? 'text-green-600' : 'text-gray-400'}`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-gray-300'}`} />
            {connected ? 'Connected' : 'Disconnected'}
          </span>
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as 'all' | 'critical' | 'high')}
            className="text-sm border border-gray-300 rounded px-2 py-1"
          >
            <option value="all">All severities</option>
            <option value="high">High + Critical</option>
            <option value="critical">Critical only</option>
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-12 text-center">
          <p className="text-gray-400">Waiting for events...</p>
          <p className="text-sm text-gray-400 mt-2">
            Findings will appear here in real time as scans complete across your repos.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((f, i) => (
            <FindingCard key={`${f.id}-${i}`} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}
