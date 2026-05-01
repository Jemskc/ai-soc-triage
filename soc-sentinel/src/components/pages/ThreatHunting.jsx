import { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#a855f7', '#22c55e', '#06b6d4', '#ec4899'];

function TopTable({ title, data, keyLabel, countLabel }) {
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-border">
        <h3 className="text-primary text-sm font-medium">{title}</h3>
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border">
            <th className="text-left text-muted px-4 py-2 font-medium">{keyLabel}</th>
            <th className="text-right text-muted px-4 py-2 font-medium">{countLabel}</th>
            <th className="text-right text-muted px-4 py-2 font-medium">%</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={row.key} className="border-b border-border hover:bg-hover transition-colors">
              <td className="px-4 py-2 font-mono text-primary">{row.key}</td>
              <td className="px-4 py-2 text-right text-muted">{row.count}</td>
              <td className="px-4 py-2 text-right">
                <div className="flex items-center justify-end gap-2">
                  <div className="w-16 bg-hover rounded-full h-1">
                    <div className="h-full rounded-full" style={{ width: `${row.pct}%`, background: COLORS[i % COLORS.length] }} />
                  </div>
                  <span className="text-muted w-8 text-right">{row.pct}%</span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function getTop(arr, key, n = 10) {
  const counts = {};
  for (const item of arr) {
    const v = item[key];
    if (v && v !== 'Unknown') counts[v] = (counts[v] || 0) + 1;
  }
  const total = arr.length;
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, count]) => ({ key: k, count, pct: Math.round((count / total) * 100) }));
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-card border border-border rounded p-2 text-xs">
      <p className="text-muted">{label}</p>
      <p className="text-primary">{payload[0].value} events</p>
    </div>
  );
};

export default function ThreatHunting({ logs }) {
  const topIPs = useMemo(() => getTop(logs, 'sourceIP'), [logs]);
  const topUsers = useMemo(() => getTop(logs, 'user'), [logs]);
  const topHosts = useMemo(() => getTop(logs, 'host'), [logs]);
  const topRules = useMemo(() => getTop(logs, 'rule', 8), [logs]);

  return (
    <div className="space-y-4 animate-fadeIn">
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-primary text-sm font-medium mb-4">Top Alert Rules (Frequency)</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={topRules} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2130" horizontal={false} />
            <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="key" tick={{ fill: '#e2e8f0', fontSize: 10 }} tickLine={false} axisLine={false} width={200} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {topRules.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TopTable title="Top Source IPs" data={topIPs} keyLabel="IP Address" countLabel="Events" />
        <TopTable title="Top Users" data={topUsers} keyLabel="Username" countLabel="Events" />
        <TopTable title="Top Hosts" data={topHosts} keyLabel="Hostname" countLabel="Events" />
      </div>
    </div>
  );
}
