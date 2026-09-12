import { GitBranch, DoorOpen, Crosshair, ArrowDown, MapPin } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

const TACTIC_COLORS = {
  'initial access': 'border-orange-500/50 bg-orange-500/10 text-orange-400',
  execution: 'border-red-500/50 bg-red-500/10 text-red-400',
  persistence: 'border-purple-500/50 bg-purple-500/10 text-purple-400',
  'privilege escalation': 'border-pink-500/50 bg-pink-500/10 text-pink-400',
  'defense evasion': 'border-blue-500/50 bg-blue-500/10 text-blue-400',
  'credential access': 'border-amber-500/50 bg-amber-500/10 text-amber-400',
  discovery: 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400',
  'lateral movement': 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400',
  collection: 'border-teal-500/50 bg-teal-500/10 text-teal-400',
  'command and control': 'border-violet-500/50 bg-violet-500/10 text-violet-400',
  exfiltration: 'border-rose-500/50 bg-rose-500/10 text-rose-400',
  impact: 'border-red-600/50 bg-red-600/10 text-red-500',
};

function tacticStyle(tactic) {
  const key = String(tactic || '').toLowerCase().replace(/-/g, ' ');
  return TACTIC_COLORS[key] || 'border-border bg-panel text-muted';
}

function attackUrl(technique) {
  const id = String(technique || '').match(/T\d{4}(?:\.\d{3})?/)?.[0];
  return id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` : null;
}

/**
 * The attack chain, reconstructed by the AI across correlated incidents.
 *
 * The previous Investigations view filtered logs by matching host, which shows
 * what happened but not how the steps relate. This orders the steps into
 * kill-chain stages and narrates the movement between them.
 */
export default function AIAttackChain({ onSelectIncident }) {
  const { campaign, isReady } = useAnalysis();
  const analysis = campaign?.investigations?.payload;

  if (!isReady || !analysis) return null;

  const chain = Array.isArray(analysis.chain) ? analysis.chain : [];
  const pivots = Array.isArray(analysis.pivots) ? analysis.pivots : [];

  return (
    <div className="space-y-4">
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
          <GitBranch size={14} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            AI-Reconstructed Attack Chain
          </span>
          {analysis.current_stage && (
            <span className="ml-auto text-[10px] text-primary">
              Reached: <span className="font-medium">{analysis.current_stage}</span>
            </span>
          )}
        </div>

        <div className="p-4 space-y-3">
          {analysis.entry_point && (
            <div className="flex items-start gap-2 p-2.5 rounded bg-panel">
              <DoorOpen size={13} className="text-orange-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-muted text-[10px] uppercase tracking-wider">Entry point</p>
                <p className="text-primary text-xs leading-relaxed">{analysis.entry_point}</p>
              </div>
            </div>
          )}

          {chain.length === 0 ? (
            <p className="text-muted text-xs">
              No ordered chain could be established from the available evidence.
            </p>
          ) : (
            <div className="space-y-0">
              {chain.map((step, i) => {
                const href = attackUrl(step.technique);
                return (
                  <div key={i}>
                    <button
                      onClick={() => step.incident_id && onSelectIncident?.(step.incident_id)}
                      className="w-full text-left flex gap-3 p-2.5 rounded hover:bg-hover transition-colors group"
                    >
                      <div className="flex flex-col items-center shrink-0">
                        <span className="w-6 h-6 rounded-full bg-panel border border-border flex items-center justify-center text-[10px] font-mono text-primary">
                          {i + 1}
                        </span>
                      </div>
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          {step.tactic && (
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${tacticStyle(step.tactic)}`}>
                              {step.tactic}
                            </span>
                          )}
                          {step.stage && (
                            <span className="text-primary text-xs font-medium">{step.stage}</span>
                          )}
                          {step.timestamp && (
                            <span className="text-muted text-[10px] font-mono ml-auto">
                              {step.timestamp}
                            </span>
                          )}
                        </div>
                        {step.narrative && (
                          <p className="text-muted text-[11px] leading-relaxed">{step.narrative}</p>
                        )}
                        <div className="flex items-center gap-2">
                          {href ? (
                            <a
                              href={href}
                              target="_blank"
                              rel="noreferrer"
                              onClick={e => e.stopPropagation()}
                              className="text-blue-400 hover:text-blue-300 text-[10px] font-mono"
                            >
                              {step.technique}
                            </a>
                          ) : step.technique ? (
                            <span className="text-muted text-[10px] font-mono">{step.technique}</span>
                          ) : null}
                          {step.incident_id && (
                            <span className="text-muted text-[10px] font-mono">{step.incident_id}</span>
                          )}
                        </div>
                      </div>
                    </button>
                    {i < chain.length - 1 && (
                      <div className="flex justify-start pl-[1.35rem]">
                        <ArrowDown size={12} className="text-muted/40" />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {pivots.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
            <Crosshair size={13} className="text-blue-400" />
            <span className="text-muted text-[10px] uppercase tracking-wider">
              Suggested pivots
            </span>
          </div>
          <div className="p-4 space-y-2">
            {pivots.map((p, i) => (
              <div key={i} className="flex items-start gap-2">
                <MapPin size={11} className="text-muted mt-0.5 shrink-0" />
                <p className="text-primary text-[11px] leading-relaxed">
                  {typeof p === 'string' ? p : p.pivot || p.suggestion || JSON.stringify(p)}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
