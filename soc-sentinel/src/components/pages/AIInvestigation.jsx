import { useState } from 'react';
import {
  Brain, HelpCircle, Search, Lightbulb, AlertTriangle, Gauge,
  ChevronDown, ChevronRight, Clock, Ban, BookOpen, ListChecks,
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

      {/* 2 + 3 — what I checked. Collapsed by default.
          The step-by-step trace is how the conclusion was reached, not the
          conclusion; leading with eleven numbered tool calls buried the one
          line an analyst actually needs. It stays one click away because a
          verdict nobody can audit is worth nothing. */}
      <details className="group">
        <summary className="flex items-center gap-1.5 mb-1.5 cursor-pointer
                            text-muted hover:text-primary list-none">
          <Search size={11} className="text-blue-400" />
          <span className="text-[10px] uppercase tracking-wider">
            How I got there — {steps.length} steps
          </span>
          <ChevronRight size={10} className="group-open:rotate-90 transition-transform" />
        </summary>
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
      </details>

      {/* 4 — why it matters */}
      <Section icon={Lightbulb} title="Why I decided that">
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

      {/* The action. A verdict with no instruction attached leaves the
          analyst to work out what it implies, which is the work the agent was
          supposed to have done. */}
      {Array.isArray(v.recommended_actions) && v.recommended_actions.length > 0 && (
        <Section icon={ListChecks} title="What to do about it">
          <ul className="space-y-1">
            {v.recommended_actions.map((a, i) => (
              <li key={i} className="text-primary text-[11px] leading-relaxed flex gap-1.5">
                <span className="text-blue-400">{i + 1}.</span>
                <span>{typeof a === 'string' ? a : (a.action || JSON.stringify(a))}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

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
              <AlertTriangle size={10} /> decided on a spent budget — lower trust
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
// What the verdict actually means, for someone who did not write the enum.
// "SUPPRESS" is not an answer to "is it malicious"; "Not malicious" is.
const CONCLUSION = {
  ESCALATE: { text: 'Malicious — escalated', cls: 'text-red-400' },
  SUPPRESS: { text: 'Not malicious — closed', cls: 'text-emerald-400' },
  UNKNOWN:  { text: 'Inconclusive — evidence did not settle it', cls: 'text-amber-400' },
};
const conclusionOf = v => CONCLUSION[v] || { text: v || 'no verdict', cls: 'text-muted' };

export default function AIInvestigation({ selectedId, onSelect }) {
  const { cases, incidentsByUrgency, isReady } = useAnalysis();
  const { events } = useLiveEvents();
  const { current: live, finished } = useLiveInvestigation(events);
  const [openId, setOpenId] = useState(selectedId || null);

  // Built from the case files, not by filtering the current incident list.
  // The funnel republishes that list per batch, so filtering it dropped every
  // case the agent had already decided.
  const rank = Object.fromEntries(
    incidentsByUrgency.map((i, n) => [i.incident_id, n]));
  const investigated = Object.values(cases || {})
    .filter(c => c?.investigation)
    .sort((a, b) => {
      const ra = rank[a.incident_id] ?? Infinity;
      const rb = rank[b.incident_id] ?? Infinity;
      if (ra !== rb) return ra - rb;
      return (b.risk?.risk_score ?? 0) - (a.risk?.risk_score ?? 0);
    });

  if (!isReady) return <p className="text-muted text-xs">No analysis yet.</p>;

  const malicious = investigated.filter(
    c => c.investigation?.verdict?.verdict === 'ESCALATE').length;
  const clean = investigated.filter(
    c => c.investigation?.verdict?.verdict === 'SUPPRESS').length;

  return (
    <div className="space-y-3">
      {/* Running now. Each case is added to the list below the moment it
          concludes — an analyst does not wait for the whole corpus. */}
      {live && (
        <div className="bg-card border border-blue-500/40 rounded-lg p-3">
          <div className="flex items-center gap-2">
            <Brain size={12} className="text-blue-400 animate-pulse" />
            <span className="text-blue-300 text-[11px] font-semibold">
              Investigating now
            </span>
            <span className="text-primary text-[11px] font-mono">{live.incidentId}</span>
            <span className="ml-auto text-muted text-[10px]">
              step {live.steps.length} · {TOOL_PLAIN[live.steps.at(-1)?.tool] || ''}
            </span>
          </div>
          {live.steps.at(-1)?.thought && (
            <p className="text-muted text-[10px] mt-1 leading-relaxed line-clamp-2">
              {live.steps.at(-1).thought}
            </p>
          )}
        </div>
      )}

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
          <Brain size={13} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            Decided by the AI
          </span>
          <span className="text-primary text-[10px]">{investigated.length}</span>
          {malicious > 0 && (
            <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 text-[9px]">
              {malicious} malicious
            </span>
          )}
          {clean > 0 && (
            <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[9px]">
              {clean} not malicious
            </span>
          )}
        </div>

        {/* Straight off the event stream, before the stored case file lands. */}
        {finished.filter(f => !cases?.[f.incidentId]).map(f => (
          <div key={`live-${f.incidentId}`}
               className="flex items-center gap-3 px-3 py-2 border-b border-border bg-emerald-500/5">
            <Brain size={11} className="text-emerald-400 shrink-0" />
            <span className="font-mono text-[10px] text-primary">{f.incidentId}</span>
            <span className={`text-[10px] font-semibold ${conclusionOf(f.verdict).cls}`}>
              {conclusionOf(f.verdict).text}
            </span>
            <span className="ml-auto text-muted text-[9px]">writing up…</span>
          </div>
        ))}

        {investigated.length === 0 && !live ? (
          <p className="text-muted text-xs p-4">
            No investigations finished yet. Each takes about 85 seconds, and every
            one is kept here as soon as it concludes.
          </p>
        ) : investigated.map(c => {
          const inv = c.investigation || {};
          const v = inv.verdict || {};
          const concl = conclusionOf(v.verdict);
          const open = openId === c.incident_id;
          return (
            <div key={c.incident_id} className="border-b border-border last:border-0">
              <button
                onClick={() => { setOpenId(open ? null : c.incident_id);
                                 if (!open) onSelect?.(c.incident_id); }}
                className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-hover transition-colors"
              >
                {open ? <ChevronDown size={12} className="text-muted shrink-0" />
                      : <ChevronRight size={12} className="text-muted shrink-0" />}
                <span className="font-mono text-[10px] text-blue-400 shrink-0 w-[112px]">
                  {c.incident_id}
                </span>
                <span className="text-muted text-[10px] shrink-0 w-[120px] truncate">
                  {c.incident?.hosts?.[0] || '—'} · {c.incident?.users?.[0] || '—'}
                </span>
                {/* The label, which is the reason this row exists. */}
                <span className={`text-[11px] font-semibold shrink-0 w-[210px] ${concl.cls}`}>
                  {concl.text}
                </span>
                <span className="text-muted text-[10px] truncate flex-1 min-w-0">
                  {v.analyst_summary || ''}
                </span>
                {Number.isFinite(v.confidence) && (
                  <span className="text-muted text-[9px] shrink-0">
                    conf {v.confidence}
                  </span>
                )}
                {Number.isFinite(v.urgency_score) && (
                  <span className="text-muted text-[9px] shrink-0">
                    urgency {v.urgency_score}/10
                  </span>
                )}
                <span className="text-muted text-[9px] shrink-0 inline-flex items-center gap-1">
                  <Clock size={9} /> {inv.elapsed_seconds}s
                </span>
              </button>

              {open && (
                <div className="px-4 pb-4 pt-1 bg-base">
                  <Reasoning caseFile={c} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
