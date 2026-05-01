import { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { exportSummary, exportCSV, exportJSON } from '../../utils/logExporter';

const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' };

export default function Reports({ logs, fileInfo }) {
  const stats = useMemo(() => {
    const byRule = {};
    const byHour = {};
    for (const l of logs) {
      byRule[l.rule] = (byRule[l.rule] || 0) + 1;
      const h = new Date(l.timestamp).getHours();
      byHour[h] = (byHour[h] || 0) + 1;
    }
    const topRules = Object.entries(byRule).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name: name.length > 30 ? name.slice(0, 30) + '…' : name, count }));
    const hourData = Array.from({ length: 24 }, (_, h) => ({ hour: `${h}:00`, count: byHour[h] || 0 }));
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const l of logs) sevCounts[l.severity] = (sevCounts[l.severity] || 0) + 1;
    const timestamps = logs.map(l => l.timestamp).filter(Boolean).sort();
    return { topRules, hourData, sevCounts, timeRange: { start: timestamps[0], end: timestamps[timestamps.length - 1] } };
  }, [logs]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div className="bg-card border border-border rounded p-2 text-xs">
        <p className="text-muted">{label}</p>
        <p className="text-primary">{payload[0].value}</p>
      </div>
    );
  };

  return (
    <div className="animate-fadeIn space-y-4">
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-primary text-sm font-medium mb-3">Summary Report</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          {Object.entries(stats.sevCounts).map(([sev, count]) => (
            <div key={sev} className="bg-panel rounded-lg p-3">
              <p className="text-muted text-xs mb-1">{sev}</p>
              <p className="text-xl font-semibold" style={{ color: SEV_COLORS[sev] }}>{count}</p>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-3 gap-3 text-xs">
          <div className="bg-panel rounded p-2">
            <p className="text-muted mb-1">Total Events</p>
            <p className="text-primary font-semibold">{logs.length.toLocaleString()}</p>
          </div>
          <div className="bg-panel rounded p-2">
            <p className="text-muted mb-1">Unique IPs</p>
            <p className="text-primary font-semibold">{new Set(logs.map(l => l.sourceIP)).size}</p>
          </div>
          <div className="bg-panel rounded p-2">
            <p className="text-muted mb-1">Time Range</p>
            <p className="text-primary font-semibold text-[10px]">
              {stats.timeRange.start ? new Date(stats.timeRange.start).toLocaleDateString() : '—'}
              {' → '}
              {stats.timeRange.end ? new Date(stats.timeRange.end).toLocaleDateString() : '—'}
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="text-primary text-sm font-medium mb-4">Events by Hour of Day</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={stats.hourData} margin={{ left: -20, right: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2130" />
              <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 9 }} tickLine={false} interval={5} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" fill="#3b82f6" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="text-primary text-sm font-medium mb-4">Top 5 Alert Rules</h3>
          <div className="space-y-2">
            {stats.topRules.map((r, i) => {
              const max = stats.topRules[0]?.count || 1;
              return (
                <div key={r.name} className="flex items-center gap-3">
                  <span className="text-muted text-[10px] w-4">{i + 1}</span>
                  <div className="flex-1">
                    <p className="text-primary text-xs truncate">{r.name}</p>
                    <div className="bg-hover rounded-full h-1 mt-1">
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${(r.count / max) * 100}%` }} />
                    </div>
                  </div>
                  <span className="text-muted text-xs">{r.count}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-primary text-sm font-medium mb-3">Export Report</h3>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => exportJSON(logs, `${fileInfo?.name ?? 'logs'}_export.json`)}
            className="px-4 py-2 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors">
            Export All Logs (.json)
          </button>
          <button onClick={() => exportCSV(logs, `${fileInfo?.name ?? 'logs'}_export.csv`)}
            className="px-4 py-2 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors">
            Export All Logs (.csv)
          </button>
          <button onClick={() => exportSummary(logs, fileInfo)}
            className="px-4 py-2 bg-blue-600 rounded text-xs text-white hover:bg-blue-500 transition-colors">
            Export Analysis Summary
          </button>
        </div>
      </div>
    </div>
  );
}
