import { useState } from 'react';
import {
  Brain, HelpCircle, Search, Lightbulb, AlertTriangle, Gauge,
  ChevronDown, ChevronRight, CheckCircle2, Clock, Ban, BookOpen,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import { useLiveEvents, useLiveInvestigation } from '../../hooks/useLiveEvents';

const TOOL_PLAIN = {
  query_identity: 'looked at the account',
  query_endpoint: 'looked at the machine',
  query_network: 'looked at network activity',
  query_asset: 'checked how important this asset is',
  check_baseline: 'compared against normal behaviour',
  search_knowledge: 'looked up the technique',
  timeline: 'built a timeline',
  find_similar_cases: 'checked past cases',
  ask_analyst: 'asked a human',
  conclude: 'reached a conclusion',
};

function Section({ icon: Icon, title, children }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1.5">
        <Icon size={11} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">{title}</span>
      </div>
      {children}
    </div>
  );
}

/** One case, told as the AI's own reasoning. */
function Reasoning({ caseFile }) {
  const [openStep, setOpenStep] = useState(null);
  const inv = caseFile.investigation || {};
  const v = inv.verdict || {};
  const inc = caseFile.incident || {};
  const steps = inv.steps || [];
  const confidence = Number.isFinite(v.confidence) ? Math.round(v.confidence * 100) : null;

  return (
    <div className="space-y-4">
      {/* 1 — why this case at all */}
      <Section icon={HelpCircle} title="Why I investigated this">
        <ul className="space-y-1">
          {(inc.signals || []).slice(0, 3).map((s, i) => (
            <li key={i} className="text-primary text-[11px] leading-relaxed">
              • {s.reason}
            </li>
          ))}
          {!inc.signals?.length && (
            <li className="text-muted text-[11px]">
              Flagged by {inc.rules_fired?.[0]?.rule || 'a detection rule'}.
            </li>
          )}
        </ul>
      </Section>

      {/* 2 + 3 — what I checked, and what came back */}
      <Section icon={Search} title={`What I checked (${steps.length} steps)`}>
        <div className="space-y-1">
          {steps.map((s, i) => {
            const refused = /already ran|no tools remain|did not come back|never called|not established/i
              .test(String(s.observation || ''));
            return (
              <div key={i} className="border border-border rounded overflow-hidden">
                <button onClick={() => setOpenStep(openStep === i ? null : i)}
                  className="w-full flex items-start gap-2 px-2 py-1.5 hover:bg-hover text-left">
                  {openStep === i ? <ChevronDown size={11} className="text-muted mt-0.5 shrink-0" />
                                  : <ChevronRight size={11} className="text-muted mt-0.5 shrink-0" />}
                  <span className="text-muted font-mono text-[10px] mt-0.5">{s.step}</span>
                  <div className="min-w-0 flex-1">
                    <span className={`text-[11px] ${refused ? 'text-amber-400' : 'text-primary'}`}>
                      {refused && <Ban size={9} className="inline mr-1" />}
                      {TOOL_PLAIN[s.tool] || s.tool}
                    </span>
                    {/* The reasoning is the point of this tab. */}
                    {s.thought && (
                      <p className="text-muted text-[10px] italic leading-relaxed">{s.thought}</p>
                    )}
                  </div>
                  {s.elapsed_seconds > 0 && (
                    <span className="text-muted text-[9px] shrink-0">{s.elapsed_seconds}s</span>
                  )}
                </button>
                {openStep === i && (
                  <pre className="px-2 pb-2 text-[10px] text-primary font-mono overflow-x-auto max-h-40 overflow-y-auto">
                    {String(s.observation || '').slice(0, 1200)}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
      </Section>

      {/* 4 — why it matters */}
      <Section icon={Lightbulb} title="What I concluded, and why it matters">
        <div className="space-y-1.5">
          <p className="text-primary text-xs leading-relaxed">{v.analyst_summary}</p>
          {v.business_impact && (
            <p className="text-muted text-[11px] leading-relaxed">{v.business_impact}</p>
          )}
          {Array.isArray(v.evidence) && v.evidence.length > 0 && (
            <div className="space-y-1 pt-1">
              {v.evidence.slice(0, 4).map((e, i) => (
                <div key={i} className="text-[10px]">
                  <span className="text-blue-400 font-mono">{e.field}</span>
                  <span className="text-primary font-mono ml-1.5 break-all">
                    {String(e.value ?? '').slice(0, 90)}
                  </span>
                  {e.why && <p className="text-muted leading-relaxed">{e.why}</p>}
                </div>
              ))}
            </div>
          )}
        </div>
      </Section>

      {/* 5 — confidence, and whether the claim is backed */}
      <Section icon={Gauge} title="How confident I am">
        <div className="flex items-center gap-3 flex-wrap text-[11px]">
          <span className="text-primary">{v.verdict}</span>
          {confidence !== null && (
            <span className="text-primary font-mono">{confidence}%</span>
          )}
          {Number.isFinite(v.urgency_score) && (
            <span className="text-muted">urgency {v.urgency_score}/10</span>
          )}
          {!inv.complete && (
            <span className="text-amber-400 inline-flex items-center gap-1">
              <AlertTriangle size={10} /> ran out of budget — needs a human
            </span>
          )}
        </div>

        <div className="mt-1.5 text-[10px]">
          {inv.grounded_in?.length > 0 ? (
            <span className="text-emerald-400 inline-flex items-center gap-1">
              <BookOpen size={10} />
              attribution backed by {inv.grounded_in.map(g => g.id).join(', ')}
            </span>
          ) : (
            <span className="text-muted">no technique lookup was performed</span>
          )}
          {inv.ungrounded_citations?.length > 0 && (
            <p className="text-amber-400 mt-0.5 inline-flex items-start gap-1">
              <AlertTriangle size={10} className="mt-0.5 shrink-0" />
              cited {inv.ungrounded_citations.join(', ')} without a lookup behind it —
              treat that attribution as unverified
            </p>
          )}
        </div>
      </Section>
    </div>
  );
}

/**
 * The AI's reasoning, as the primary view rather than a detail panel.
 *
 * Structured as the questions an analyst would ask if a colleague handed them
 * a conclusion: why did you look at this, what did you check, what did you
 * find, why does it matter, and how sure are you.
 */
export default function AIInvestigation({ selectedId, onSelect }) {
  const { cases, incidentsByUrgency, isReady } = useAnalysis();
  const { events } = useLiveEvents();
  const live = useLiveInvestigation(events);

  const investigated = incidentsByUrgency.filter(i => cases?.[i.incident_id]?.investigation);
  const current = selectedId && cases?.[selectedId]
    ? cases[selectedId]
    : (investigated[0] ? cases[investigated[0].incident_id] : null);

  if (!isReady) {
    return <p className="text-muted text-xs">No analysis yet.</p>;
  }

  return (
    <div className="flex gap-4 h-full">
      <div className="w-56 shrink-0 space-y-1 overflow-y-auto">
        {live && (
          <div className="mb-2 p-2 rounded border border-blue-500/40 bg-blue-500/5">
            <div className="flex items-center gap-1.5">
              <Brain size={11} className="text-blue-400 animate-pulse" />
              <span className="text-blue-300 text-[10px] font-semibold">investigating now</span>
            </div>
            <p className="text-primary text-[10px] font-mono mt-0.5">{live.incidentId}</p>
            <p className="text-muted text-[10px]">
              {live.steps.length} steps · {TOOL_PLAIN[live.steps.at(-1)?.tool] || ''}
            </p>
          </div>
        )}

        <p className="text-muted text-[10px] uppercase tracking-wider px-1 mb-1">
          Investigated ({investigated.length})
        </p>
        {investigated.map(i => {
          const c = cases[i.incident_id];
          const v = c?.investigation?.verdict || {};
          const active = current?.incident_id === i.incident_id;
          return (
            <button key={i.incident_id}
              onClick={() => onSelect?.(i.incident_id)}
              className={`w-full text-left px-2 py-1.5 rounded transition-colors ${
                active ? 'bg-hover' : 'hover:bg-panel'}`}>
              <p className="text-primary text-[10px] font-mono truncate">{i.incident_id}</p>
              <p className="text-muted text-[10px] truncate">{i.hosts?.[0]}</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className={`text-[9px] ${
                  v.verdict === 'ESCALATE' ? 'text-red-400'
                    : v.verdict === 'SUPPRESS' ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {v.verdict || '—'}
                </span>
                <span className="text-muted text-[9px]">
                  {c?.investigation?.step_count} steps
                </span>
              </div>
            </button>
          );
        })}
      </div>

      <div className="flex-1 min-w-0 overflow-y-auto">
        {current ? (
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
              <Brain size={13} className="text-blue-400" />
              <span className="text-primary text-xs font-mono">{current.incident_id}</span>
              <span className="text-muted text-[10px]">
                {current.incident?.hosts?.[0]}
              </span>
              <span className="ml-auto text-muted text-[10px] inline-flex items-center gap-1">
                <Clock size={9} /> {current.investigation?.elapsed_seconds}s
              </span>
            </div>
            <div className="p-4">
              <Reasoning caseFile={current} />
            </div>
          </div>
        ) : (
          <p className="text-muted text-xs">
            No completed investigations yet — the AI is still working.
          </p>
        )}
      </div>
    </div>
  );
}
