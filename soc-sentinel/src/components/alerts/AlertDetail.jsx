import { X, Shield, Globe, User, Monitor, Hash, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { useState } from 'react';
import { severityBg, severityColor } from '../../utils/severityUtils';
import { getMitreTechnique } from '../../utils/mitreMapper';

export default function AlertDetail({ alert, onClose }) {
  const [rawExpanded, setRawExpanded] = useState(false);
  if (!alert) return null;

  const mitre = alert.mitre || getMitreTechnique(alert.rule, alert.message).technique;

  const fields = [
    { icon: Hash, label: 'Alert ID', value: alert.id },
    { icon: Clock, label: 'Timestamp', value: new Date(alert.timestamp).toLocaleString() },
    { icon: Shield, label: 'Rule', value: alert.rule },
    { icon: Globe, label: 'Source IP', value: alert.sourceIP },
    { icon: Globe, label: 'Dest IP', value: alert.destIP },
    { icon: User, label: 'User', value: alert.user },
    { icon: Monitor, label: 'Host', value: alert.host },
    { icon: Hash, label: 'MITRE', value: mitre },
    { icon: Hash, label: 'Source', value: alert.source },
    { icon: Hash, label: 'Status', value: alert.status },
  ];

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden animate-fadeIn">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${severityBg(alert.severity)}`}>
            {alert.severity}
          </span>
          <span className="text-primary text-sm font-medium">{alert.id}</span>
        </div>
        <button onClick={onClose} className="text-muted hover:text-primary transition-colors">
          <X size={16} />
        </button>
      </div>

      <div className="p-4 space-y-4">
        <p className="text-primary text-xs leading-relaxed border-l-2 pl-3" style={{ borderColor: severityColor(alert.severity) }}>
          {alert.message}
        </p>

        <div className="grid grid-cols-2 gap-2">
          {fields.map(({ icon: Icon, label, value }) => (
            <div key={label} className="bg-panel rounded p-2">
              <div className="flex items-center gap-1.5 mb-0.5">
                <Icon size={10} className="text-muted shrink-0" />
                <span className="text-muted text-[10px] uppercase tracking-wider">{label}</span>
              </div>
              <span className="text-primary text-xs font-mono truncate block">{value || '—'}</span>
            </div>
          ))}
        </div>

        <div className="border border-border rounded overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-3 py-2 bg-panel text-muted text-xs hover:text-primary transition-colors"
            onClick={() => setRawExpanded(p => !p)}
          >
            <span>Raw Log Entry</span>
            {rawExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
          {rawExpanded && (
            <pre className="text-[10px] text-primary bg-base p-3 overflow-auto max-h-48 font-mono">
              {JSON.stringify(alert._raw || alert, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
