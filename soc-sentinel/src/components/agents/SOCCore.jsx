import { Bot, Search, BookOpen, Crosshair, ShieldOff, Scale, ArrowRight, Database } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import TelemetryCoverage from './TelemetryCoverage';

const AGENTS = [
  { name: 'intel',    icon: BookOpen,  label: 'Intel Agent',    blurb: 'Establishes what the technique is and what an adversary does next.' },
  { name: 'triage',   icon: Search,    label: 'Triage Agent',   blurb: 'Judges whether it is real and how urgent, on grounded evidence.' },
  { name: 'hunt',     icon: Crosshair, label: 'Hunt Agent',     blurb: 'Finds leads the rules missed, including in blind spots.' },
  { name: 'response', icon: ShieldOff, label: 'Response Agent', blurb: 'Proposes containment. Never executes without approval.' },
];

const BAND_TONE = {
  critical: 'text-red-400', high: 'text-orange-400',
  medium: 'text-amber-400', low: 'text-emerald-400',
};

/**
 * The SOC core: which agents ran, how the queue is prioritised, and what the
 * platform can actually see.
 *
 * Exists because the architecture is the differentiator. A reviewer should be
 * able to understand the pipeline without reading the code.
 */
export default function SOCCore({ onSelectIncident }) {
  const { queue, telemetryCoverage, huntFindings, engineStats, isReady, cases } = useAnalysis();

  if (!isReady) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted">
        <div className="text-center space-y-2">
          <Bot size={28} className="mx-auto opacity-40" />
          <p className="text-primary font-medium">AI SOC Core</p>
          <p className="text-xs">Run an analysis to see the agents work.</p>
        </div>
      </div>
    );
  }

  const caseCount = Object.keys(cases || {}).length;

  return (
    <div className="space-y-4">
      {/* Pipeline */}
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
          <Bot size={14} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            Agent Orchestrator
          </span>
          {engineStats && (
            <span className="ml-auto text-muted text-[10px] font-mono">
              {engineStats.calls} model calls · {engineStats.mean_seconds}s avg ·{' '}
              {engineStats.parse_failures} parse failures
            </span>
          )}
        </div>

        <div className="p-4 space-y-3">
          <div className="flex items-center gap-2 text-[11px] text-muted flex-wrap">
            <span className="inline-flex items-center gap-1 text-primary">
              <Database size={11} /> Evidence Engine
            </span>
            <ArrowRight size={11} />
            <span>Intel</span>
            <ArrowRight size={11} />
            <span>Triage</span>
            <ArrowRight size={11} />
            <span className="inline-flex items-center gap-1 text-primary">
              <Scale size={11} /> Risk Engine
            </span>
            <ArrowRight size={11} />
            <span>Response</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {AGENTS.map(a => {
              const Icon = a.icon;
              return (
                <div key={a.name} className="bg-panel rounded p-2.5">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <Icon size={11} className="text-blue-400" />
                    <span className="text-primary text-[11px] font-medium">{a.label}</span>
                  </div>
                  <p className="text-muted text-[10px] leading-relaxed">{a.blurb}</p>
                </div>
              );
            })}
          </div>

          <p className="text-muted text-[10px] leading-relaxed border-t border-border pt-2">
            Agents supply judgement; the Risk Engine fuses it with deterministic
            weights, so the same case always scores the same and every point is
            attributable to a named factor.
          </p>
        </div>
      </div>

      <TelemetryCoverage coverage={telemetryCoverage} />

      {/* Work queue */}
      {queue?.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
            <Scale size={13} className="text-blue-400" />
            <span className="text-muted text-[10px] uppercase tracking-wider">
              Analyst Queue — by fused risk
            </span>
            <span className="ml-auto text-muted text-[10px]">
              {caseCount} case file{caseCount === 1 ? '' : 's'}
            </span>
          </div>
          <div className="divide-y divide-border max-h-80 overflow-y-auto">
            {queue.map(q => (
              <button
                key={q.incident_id}
                onClick={() => onSelectIncident?.(q.incident_id)}
                className="w-full flex items-center gap-3 px-4 py-2 hover:bg-hover transition-colors text-left"
              >
                <span className={`font-mono text-xs tabular-nums w-10 shrink-0 ${BAND_TONE[q.band] || 'text-muted'}`}>
                  {q.risk_score}
                </span>
                <span className="text-primary text-[11px] font-mono truncate">{q.incident_id}</span>
                <span className={`text-[10px] uppercase ${BAND_TONE[q.band] || 'text-muted'}`}>
                  {q.band}
                </span>
                <span className="ml-auto text-muted text-[10px]">
                  {String(q.action || '').replace(/_/g, ' ')}
                </span>
                {q.requires_approval && (
                  <span className="text-amber-400 text-[9px] uppercase tracking-wider shrink-0">
                    approval
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Hunt leads */}
      {huntFindings?.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
            <Crosshair size={13} className="text-blue-400" />
            <span className="text-muted text-[10px] uppercase tracking-wider">
              Hunt Agent — leads across all cases
            </span>
          </div>
          <div className="divide-y divide-border">
            {huntFindings.map((f, i) => (
              <div key={i} className="p-3">
                <p className="text-primary text-[11px] leading-relaxed">{f.summary}</p>
                {f.data?.rationale && (
                  <p className="text-muted text-[10px] mt-1 leading-relaxed">{f.data.rationale}</p>
                )}
                {f.data?.query && (
                  <code className="inline-block mt-1.5 px-1.5 py-0.5 rounded bg-panel text-blue-400 text-[10px] font-mono">
                    {f.data.query}
                  </code>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
