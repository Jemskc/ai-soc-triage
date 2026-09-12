import { useState } from 'react';
import { BookOpen, ShieldOff, Trash2, RefreshCw, UserCheck, ChevronRight } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import { severityBg } from '../../utils/severityUtils';

const PHASES = [
  { key: 'contain', label: 'Contain', icon: ShieldOff, tone: 'text-red-400' },
  { key: 'eradicate', label: 'Eradicate', icon: Trash2, tone: 'text-amber-400' },
  { key: 'recover', label: 'Recover', icon: RefreshCw, tone: 'text-emerald-400' },
];

function PhaseList({ phase, steps }) {
  if (!Array.isArray(steps) || steps.length === 0) return null;
  const Icon = phase.icon;
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1.5">
        <Icon size={11} className={phase.tone} />
        <span className="text-muted text-[10px] uppercase tracking-wider">{phase.label}</span>
      </div>
      <ol className="space-y-1">
        {steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-[11px] text-primary">
            <span className="text-muted font-mono shrink-0">{i + 1}.</span>
            <span className="leading-relaxed">{s}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/**
 * Response playbooks, selected and filled per incident by the AI from the
 * knowledge base's playbook chunks.
 *
 * The nav item for this tab existed with nothing behind it. Generating the
 * procedure per incident is more useful than a static library, because the
 * steps name the actual hosts and accounts involved.
 */
export default function Playbooks() {
  const { incidentsByUrgency, verdictFor, isReady } = useAnalysis();
  const [selectedId, setSelectedId] = useState(null);

  if (!isReady) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted">
        <div className="text-center space-y-2">
          <BookOpen size={28} className="mx-auto opacity-40" />
          <p className="text-primary font-medium">Playbooks</p>
          <p className="text-xs">Run an analysis to generate response procedures per incident.</p>
        </div>
      </div>
    );
  }

  const withPlaybooks = incidentsByUrgency.filter(i => verdictFor(i.incident_id));
  const selected = withPlaybooks.find(i => i.incident_id === selectedId) || withPlaybooks[0];
  const verdict = selected ? verdictFor(selected.incident_id) : null;
  const playbook = verdict?.playbook || verdict;

  return (
    <div className="flex gap-4 h-full">
      <div className="w-64 shrink-0 space-y-1 overflow-y-auto">
        <p className="text-muted text-[10px] uppercase tracking-wider px-1 mb-2">
          Incidents ({withPlaybooks.length})
        </p>
        {withPlaybooks.map(inc => {
          const v = verdictFor(inc.incident_id);
          const active = selected?.incident_id === inc.incident_id;
          return (
            <button
              key={inc.incident_id}
              onClick={() => setSelectedId(inc.incident_id)}
              className={`w-full text-left px-2.5 py-2 rounded transition-colors ${
                active ? 'bg-hover' : 'hover:bg-panel'
              }`}
            >
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${severityBg(inc.severity)}`}>
                  {inc.severity}
                </span>
                {Number.isFinite(v?.urgency_score) && (
                  <span className="text-muted text-[10px] font-mono ml-auto">
                    {v.urgency_score}/10
                  </span>
                )}
              </div>
              <p className="text-primary text-[11px] font-mono truncate">{inc.incident_id}</p>
              <p className="text-muted text-[10px] truncate">
                {inc.hosts?.[0] || 'unknown host'}
              </p>
            </button>
          );
        })}
      </div>

      <div className="flex-1 min-w-0 overflow-y-auto">
        {!selected ? (
          <p className="text-muted text-xs">No incidents with AI analysis yet.</p>
        ) : (
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
              <BookOpen size={13} className="text-blue-400" />
              <span className="text-primary text-sm font-medium">
                {playbook?.playbook_name || 'Response Procedure'}
              </span>
              <span className="ml-auto text-muted text-[10px] font-mono">
                {selected.incident_id}
              </span>
            </div>

            <div className="p-4 space-y-4">
              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                {(selected.hosts || []).slice(0, 4).map(h => (
                  <span key={h} className="px-1.5 py-0.5 rounded bg-panel text-primary font-mono">
                    {h}
                  </span>
                ))}
                {(selected.users || []).slice(0, 4).map(u => (
                  <span key={u} className="px-1.5 py-0.5 rounded bg-panel text-purple-400 font-mono">
                    {u}
                  </span>
                ))}
              </div>

              {playbook?.analyst_summary && (
                <p className="text-muted text-xs leading-relaxed">{playbook.analyst_summary}</p>
              )}

              {PHASES.map(phase => (
                <PhaseList key={phase.key} phase={phase} steps={playbook?.[phase.key]} />
              ))}

              {/* Recommended actions stand in when a dedicated playbook has not
                  been generated for this incident yet. */}
              {!playbook?.contain && Array.isArray(playbook?.recommended_actions) && (
                <PhaseList
                  phase={PHASES[0]}
                  steps={playbook.recommended_actions}
                />
              )}

              {playbook?.escalate_to && (
                <div className="flex items-center gap-1.5 pt-3 border-t border-border">
                  <UserCheck size={11} className="text-blue-400" />
                  <span className="text-muted text-[10px] uppercase tracking-wider">
                    Escalate to
                  </span>
                  <span className="text-primary text-xs">{playbook.escalate_to}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
