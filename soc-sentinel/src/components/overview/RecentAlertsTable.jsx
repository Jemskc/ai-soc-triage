import { severityBg } from '../../utils/severityUtils';

export default function RecentAlertsTable({ logs, onSelect }) {
  const recent = logs.slice(0, 10);

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h3 className="text-primary text-sm font-medium">Recent Alerts</h3>
        <span className="text-muted text-xs">{logs.length} total</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left text-muted px-4 py-2 font-medium">Severity</th>
              <th className="text-left text-muted px-4 py-2 font-medium">Time</th>
              <th className="text-left text-muted px-4 py-2 font-medium">Rule</th>
              <th className="text-left text-muted px-4 py-2 font-medium">Source IP</th>
              <th className="text-left text-muted px-4 py-2 font-medium">User</th>
            </tr>
          </thead>
          <tbody>
            {recent.map(log => (
              <tr
                key={log.id}
                className="border-b border-border hover:bg-hover cursor-pointer transition-colors"
                onClick={() => onSelect(log)}
              >
                <td className="px-4 py-2">
                  <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold ${severityBg(log.severity)}`}>
                    {log.severity}
                  </span>
                </td>
                <td className="px-4 py-2 text-muted font-mono">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </td>
                <td className="px-4 py-2 text-primary max-w-[200px] truncate">{log.rule}</td>
                <td className="px-4 py-2 text-muted font-mono">{log.sourceIP}</td>
                <td className="px-4 py-2 text-muted">{log.user}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
