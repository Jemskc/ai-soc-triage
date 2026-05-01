import { useMemo } from 'react';

export default function TopSourcesTable({ logs }) {
  const rows = useMemo(() => {
    const counts = {};
    for (const l of logs) counts[l.sourceIP] = (counts[l.sourceIP] || 0) + 1;
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const max = sorted[0]?.[1] || 1;
    return sorted.map(([ip, count]) => ({ ip, count, pct: Math.round((count / logs.length) * 100), bar: Math.round((count / max) * 100) }));
  }, [logs]);

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-primary text-sm font-medium mb-4">Top Source IPs</h3>
      <div className="space-y-2">
        {rows.map(r => (
          <div key={r.ip} className="flex items-center gap-3">
            <span className="text-primary font-mono text-xs w-32 shrink-0">{r.ip}</span>
            <div className="flex-1 bg-hover rounded-full h-1.5 overflow-hidden">
              <div className="h-full bg-blue-500 rounded-full transition-all" style={{ width: `${r.bar}%` }} />
            </div>
            <span className="text-muted text-xs w-8 text-right">{r.count}</span>
            <span className="text-muted text-xs w-8 text-right">{r.pct}%</span>
          </div>
        ))}
        {!rows.length && <p className="text-muted text-xs">No data</p>}
      </div>
    </div>
  );
}
