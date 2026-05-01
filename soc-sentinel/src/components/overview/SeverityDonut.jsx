import { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' };

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  return (
    <div className="bg-card border border-border rounded p-2 text-xs">
      <span style={{ color: COLORS[name] }}>{name}: {value}</span>
    </div>
  );
};

export default function SeverityDonut({ logs }) {
  const data = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const l of logs) counts[l.severity] = (counts[l.severity] || 0) + 1;
    return Object.entries(counts).map(([name, value]) => ({ name, value })).filter(d => d.value > 0);
  }, [logs]);

  const total = logs.length;

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-primary text-sm font-medium mb-4">Alerts by Severity</h3>
      <div className="relative" style={{ height: 180 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={2} dataKey="value">
              {data.map(entry => (
                <Cell key={entry.name} fill={COLORS[entry.name]} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-bold text-primary">{total.toLocaleString()}</span>
          <span className="text-muted text-xs">Total</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
        {data.map(d => (
          <div key={d.name} className="flex items-center gap-1.5 text-xs">
            <span className="w-2 h-2 rounded-full" style={{ background: COLORS[d.name] }} />
            <span className="text-muted">{d.name}</span>
            <span className="text-primary">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
