import { useMemo } from 'react';
import { Monitor } from 'lucide-react';
import { severityColor } from '../../utils/severityUtils';

export default function Assets({ logs }) {
  const assets = useMemo(() => {
    const map = {};
    for (const l of logs) {
      const h = l.host;
      if (!h || h === 'Unknown') continue;
      if (!map[h]) map[h] = { host: h, events: 0, users: new Set(), criticalCount: 0, highCount: 0, topSev: 'LOW', lastSeen: l.timestamp };
      map[h].events++;
      if (l.user && l.user !== 'Unknown') map[h].users.add(l.user);
      if (l.severity === 'CRITICAL') map[h].criticalCount++;
      if (l.severity === 'HIGH') map[h].highCount++;
      if (new Date(l.timestamp) > new Date(map[h].lastSeen)) map[h].lastSeen = l.timestamp;
    }
    return Object.values(map)
      .map(a => ({
        ...a,
        users: [...a.users],
        topSev: a.criticalCount > 0 ? 'CRITICAL' : a.highCount > 0 ? 'HIGH' : 'MEDIUM',
      }))
      .sort((a, b) => b.criticalCount - a.criticalCount || b.events - a.events);
  }, [logs]);

  return (
    <div className="animate-fadeIn space-y-4">
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-card border border-border rounded-lg p-4">
          <p className="text-muted text-xs mb-1">Total Hosts</p>
          <p className="text-2xl font-semibold text-primary">{assets.length}</p>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <p className="text-muted text-xs mb-1">Hosts with Critical Alerts</p>
          <p className="text-2xl font-semibold text-red-400">{assets.filter(a => a.criticalCount > 0).length}</p>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <p className="text-muted text-xs mb-1">Unique Users Seen</p>
          <p className="text-2xl font-semibold text-purple-400">{new Set(logs.map(l => l.user).filter(u => u && u !== 'Unknown')).size}</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-primary text-sm font-medium">Asset Inventory ({assets.length})</h3>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left text-muted px-4 py-2 font-medium">Host</th>
                <th className="text-left text-muted px-4 py-2 font-medium">Risk</th>
                <th className="text-right text-muted px-4 py-2 font-medium">Events</th>
                <th className="text-right text-muted px-4 py-2 font-medium">Critical</th>
                <th className="text-left text-muted px-4 py-2 font-medium">Users</th>
                <th className="text-left text-muted px-4 py-2 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {assets.map(a => (
                <tr key={a.host} className="border-b border-border hover:bg-hover transition-colors">
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <Monitor size={12} style={{ color: severityColor(a.topSev) }} />
                      <span className="text-primary font-mono">{a.host}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className="text-[10px] font-semibold" style={{ color: severityColor(a.topSev) }}>
                      {a.topSev}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right text-muted">{a.events}</td>
                  <td className="px-4 py-2 text-right text-red-400">{a.criticalCount || '—'}</td>
                  <td className="px-4 py-2 text-muted max-w-[150px] truncate">{a.users.join(', ') || '—'}</td>
                  <td className="px-4 py-2 text-muted">{new Date(a.lastSeen).toLocaleString()}</td>
                </tr>
              ))}
              {!assets.length && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-muted">No asset data</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
