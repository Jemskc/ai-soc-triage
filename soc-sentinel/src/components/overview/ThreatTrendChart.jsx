import { useMemo } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' };

function bucketLogs(logs) {
  if (!logs.length) return [];
  const times = logs.map(l => new Date(l.timestamp).getTime()).filter(t => !isNaN(t));
  if (!times.length) return [];
  const min = Math.min(...times);
  const max = Math.max(...times);
  const span = max - min;
  const bucketMs = span < 2 * 3600_000 ? 60_000 : 3600_000;
  const buckets = {};
  for (const log of logs) {
    const t = new Date(log.timestamp).getTime();
    if (isNaN(t)) continue;
    const key = Math.floor((t - min) / bucketMs);
    if (!buckets[key]) buckets[key] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, _t: min + key * bucketMs };
    buckets[key][log.severity] = (buckets[key][log.severity] || 0) + 1;
  }
  return Object.values(buckets)
    .sort((a, b) => a._t - b._t)
    .map(b => {
      const d = new Date(b._t);
      const label = span < 2 * 3600_000
        ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      return { time: label, CRITICAL: b.CRITICAL, HIGH: b.HIGH, MEDIUM: b.MEDIUM, LOW: b.LOW };
    });
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-card border border-border rounded p-3 text-xs">
      <p className="text-muted mb-1">{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: p.color }}>{p.dataKey}: {p.value}</p>
      ))}
    </div>
  );
};

export default function ThreatTrendChart({ logs }) {
  const data = useMemo(() => bucketLogs(logs), [logs]);

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-primary text-sm font-medium mb-4">Threat Activity Timeline</h3>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2130" />
          <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip content={<CustomTooltip />} />
          <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11, color: '#64748b' }} />
          {Object.entries(SEV_COLORS).map(([sev, color]) => (
            <Line key={sev} type="monotone" dataKey={sev} stroke={color} strokeWidth={2} dot={false} activeDot={{ r: 3 }} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
