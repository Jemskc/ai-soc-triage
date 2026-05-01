import { useMemo } from 'react';
import { AlertTriangle, Info, Shield } from 'lucide-react';
import { severityColor } from '../../utils/severityUtils';
import MitreCards from '../MitreCards';

function TimelineEntry({ log, isSelected }) {
  const color = severityColor(log.severity);
  const Icon = log.severity === 'CRITICAL' ? AlertTriangle : log.severity === 'HIGH' ? Shield : Info;

  return (
    <div className={`flex gap-3 p-3 rounded transition-colors ${isSelected ? 'bg-hover border border-border' : ''}`}>
      <div className="flex flex-col items-center">
        <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ background: `${color}20`, border: `1px solid ${color}` }}>
          <Icon size={14} style={{ color }} />
        </div>
        <div className="w-px flex-1 mt-1" style={{ background: `${color}30`, minHeight: 16 }} />
      </div>
      <div className="flex-1 min-w-0 pb-2">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-primary text-xs font-medium truncate">{log.rule}</span>
          <span className="text-muted text-[10px] shrink-0">{new Date(log.timestamp).toLocaleTimeString()}</span>
        </div>
        <p className="text-muted text-xs leading-relaxed line-clamp-2">{log.message}</p>
        <div className="flex gap-3 mt-1.5">
          {log.sourceIP !== 'Unknown' && <span className="text-[10px] text-blue-400 font-mono">{log.sourceIP}</span>}
          {log.user !== 'Unknown' && <span className="text-[10px] text-purple-400">{log.user}</span>}
          {log.host !== 'Unknown' && <span className="text-[10px] text-muted">{log.host}</span>}
        </div>
      </div>
    </div>
  );
}

export default function InvestigationTimeline({ logs, selectedAlert }) {
  const related = useMemo(() => {
    if (!selectedAlert) return logs.slice(0, 20);
    return logs
      .filter(l =>
        l.id !== selectedAlert.id && (
          l.sourceIP === selectedAlert.sourceIP ||
          l.user === selectedAlert.user ||
          l.host === selectedAlert.host
        )
      )
      .slice(0, 50);
  }, [logs, selectedAlert]);

  return (
    <div className="animate-fadeIn space-y-4">
      {selectedAlert && (
        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="text-primary text-sm font-medium mb-2">Investigation Context</h3>
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div className="bg-panel rounded p-2">
              <p className="text-muted mb-0.5">Pivot: Source IP</p>
              <p className="text-blue-400 font-mono">{selectedAlert.sourceIP}</p>
            </div>
            <div className="bg-panel rounded p-2">
              <p className="text-muted mb-0.5">Pivot: User</p>
              <p className="text-purple-400">{selectedAlert.user}</p>
            </div>
            <div className="bg-panel rounded p-2">
              <p className="text-muted mb-0.5">Pivot: Host</p>
              <p className="text-primary">{selectedAlert.host}</p>
            </div>
          </div>
          <p className="text-muted text-xs mt-2">
            Showing {related.length} related events that share the same source IP, user, or host.
          </p>
        </div>
      )}

      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-primary text-sm font-medium mb-3">MITRE ATT&CK Coverage</h3>
        <MitreCards logs={related.length ? related : logs.slice(0, 100)} />
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-primary text-sm font-medium">
            {selectedAlert ? `Related Events` : 'Recent Event Timeline'}
          </h3>
        </div>
        <div className="p-3 overflow-y-auto max-h-[500px]">
          {related.length === 0 && (
            <p className="text-muted text-xs text-center py-6">
              {selectedAlert ? 'No related events found for this alert.' : 'Select an alert to see its investigation timeline.'}
            </p>
          )}
          {related.map(log => (
            <TimelineEntry key={log.id} log={log} isSelected={log.id === selectedAlert?.id} />
          ))}
        </div>
      </div>
    </div>
  );
}
