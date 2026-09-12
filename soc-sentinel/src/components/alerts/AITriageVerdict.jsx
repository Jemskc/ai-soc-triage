import { useState } from 'react';
import {
  ShieldAlert, ShieldCheck, HelpCircle, BookOpen, ThumbsUp, ThumbsDown,
  ChevronDown, ChevronUp, AlertTriangle, ExternalLink, Gauge,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

const VERDICT_STYLES = {
  ESCALATE: { icon: ShieldAlert, cls: 'bg-red-500/15 text-red-400 border-red-500/40', label: 'ESCALATE' },
  SUPPRESS: { icon: ShieldCheck, cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40', label: 'SUPPRESS' },
  UNKNOWN: { icon: HelpCircle, cls: 'bg-amber-500/15 text-amber-400 border-amber-500/40', label: 'UNKNOWN' },
};

function attackUrl(techniqueId) {
  const clean = String(techniqueId || '').match(/T\d{4}(?:\.\d{3})?/)?.[0];
  if (!clean) return null;
  return `https://attack.mitre.org/techniques/${clean.replace('.', '/')}/`;
}

function UrgencyMeter({ score }) {
  const value = Number.isFinite(score) ? Math.max(0, Math.min(10, score)) : 0;
  const tone = value >= 8 ? 'bg-red-500' : value >= 5 ? 'bg-amber-500' : 'bg-emerald-500';
  return (
    <div className="flex items-center gap-2">
      <Gauge size={12} className="text-muted shrink-0" />
      <div className="flex-1 h-1.5 bg-hover rounded-full overflow-hidden min-w-[60px]">
        <div className={`h-full rounded-full ${tone}`} style={{ width: `${value * 10}%` }} />
      </div>
      <span className="text-primary text-xs font-mono tabular-nums">{value}/10</span>
    </div>
  );
}

/**
 * Renders the AI's verdict for one incident.
 *
 * Three things here are deliberate, and they are what separate this from a
 * chatbot answer pasted into a panel:
 *   - the evidence list names the actual log fields behind the verdict
 *   - the sources are the retrieved knowledge chunks, so grounding is clickable
 *   - agree/disagree is always available, because the analyst overrules the model
 */
export default function AITriageVerdict({ incidentId, verdict, knowledge = [], ungrounded = [] }) {
  const { sendFeedback } = useAnalysis();
  const [feedback, setFeedback] = useState(null);
  const [showSources, setShowSources] = useState(false);

  if (!verdict) {
    return (
      <div className="border border-border rounded p-3 text-muted text-xs">
        No AI analysis for this incident yet. Run an analysis to populate it.
      </div>
    );
  }

  const style = VERDICT_STYLES[String(verdict.verdict || '').toUpperCase()] || VERDICT_STYLES.UNKNOWN;
  const VerdictIcon = style.icon;
  const confidence = Number.isFinite(verdict.confidence) ? Math.round(verdict.confidence * 100) : null;
  const techniqueHref = attackUrl(verdict.mitre_technique);

  async function record(agree) {
    setFeedback(agree ? 'agree' : 'disagree');
    await sendFeedback(incidentId, agree);
  }

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] font-semibold ${style.cls}`}>
          <VerdictIcon size={12} />
          {style.label}
        </span>
        <span className="text-muted text-[10px] uppercase tracking-wider">AI Triage Verdict</span>
        <div className="ml-auto flex items-center gap-3">
          {confidence !== null && (
            <span className="text-muted text-[10px]">confidence {confidence}%</span>
          )}
          {verdict.severity_confirmed && (
            <span className="text-muted text-[10px] uppercase">{verdict.severity_confirmed}</span>
          )}
        </div>
      </div>

      <div className="p-3 space-y-3">
        <UrgencyMeter score={verdict.urgency_score} />

        {verdict.analyst_summary && (
          <p className="text-primary text-xs leading-relaxed">{verdict.analyst_summary}</p>
        )}

        {/* The model was told it may only cite techniques present in the
            retrieved knowledge. If it cited something else, say so rather than
            rendering the attribution as if it were trustworthy. */}
        {ungrounded.length > 0 && (
          <div className="flex items-start gap-2 p-2 rounded bg-amber-500/10 border border-amber-500/30">
            <AlertTriangle size={12} className="text-amber-400 mt-0.5 shrink-0" />
            <p className="text-amber-300 text-[11px] leading-relaxed">
              Ungrounded citation: {ungrounded.join(', ')} was not in the retrieved
              knowledge. Treat this attribution as unverified.
            </p>
          </div>
        )}

        {verdict.mitre_technique && (
          <div className="flex items-center gap-2">
            <span className="text-muted text-[10px] uppercase tracking-wider">Technique</span>
            {techniqueHref ? (
              <a href={techniqueHref} target="_blank" rel="noreferrer"
                 className="text-blue-400 hover:text-blue-300 text-xs font-mono inline-flex items-center gap-1">
                {verdict.mitre_technique}
                <ExternalLink size={10} />
              </a>
            ) : (
              <span className="text-primary text-xs font-mono">{verdict.mitre_technique}</span>
            )}
          </div>
        )}

        {Array.isArray(verdict.evidence) && verdict.evidence.length > 0 && (
          <div>
            <p className="text-muted text-[10px] uppercase tracking-wider mb-1.5">Evidence</p>
            <div className="space-y-1.5">
              {verdict.evidence.map((e, i) => (
                <div key={i} className="bg-panel rounded p-2 text-[11px]">
                  <div className="flex items-baseline gap-2 flex-wrap">
                    <span className="text-blue-400 font-mono">{e.field}</span>
                    <span className="text-primary font-mono break-all">{String(e.value ?? '')}</span>
                  </div>
                  {e.why && <p className="text-muted mt-0.5 leading-relaxed">{e.why}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {verdict.false_positive_likelihood && (
          <div className="text-[11px]">
            <span className="text-muted uppercase tracking-wider text-[10px]">False positive likelihood </span>
            <span className="text-primary">{verdict.false_positive_likelihood}</span>
            {verdict.false_positive_reason && (
              <p className="text-muted mt-0.5 leading-relaxed">{verdict.false_positive_reason}</p>
            )}
          </div>
        )}

        {Array.isArray(verdict.recommended_actions) && verdict.recommended_actions.length > 0 && (
          <div>
            <p className="text-muted text-[10px] uppercase tracking-wider mb-1.5">Recommended actions</p>
            <ol className="space-y-1">
              {verdict.recommended_actions.map((a, i) => (
                <li key={i} className="flex gap-2 text-[11px] text-primary">
                  <span className="text-muted font-mono shrink-0">{i + 1}.</span>
                  <span className="leading-relaxed">{a}</span>
                </li>
              ))}
            </ol>
          </div>
        )}

        {Array.isArray(verdict.investigation_steps) && verdict.investigation_steps.length > 0 && (
          <div>
            <p className="text-muted text-[10px] uppercase tracking-wider mb-1.5">Next steps to confirm</p>
            <ol className="space-y-1">
              {verdict.investigation_steps.map((s, i) => (
                <li key={i} className="flex gap-2 text-[11px] text-primary">
                  <span className="text-muted font-mono shrink-0">{i + 1}.</span>
                  <span className="leading-relaxed">{s}</span>
                </li>
              ))}
            </ol>
          </div>
        )}

        {knowledge.length > 0 && (
          <div className="border border-border rounded overflow-hidden">
            <button
              onClick={() => setShowSources(s => !s)}
              className="w-full flex items-center justify-between px-2.5 py-1.5 bg-panel text-muted text-[11px] hover:text-primary transition-colors"
            >
              <span className="inline-flex items-center gap-1.5">
                <BookOpen size={11} />
                Grounded in {knowledge.length} knowledge source{knowledge.length === 1 ? '' : 's'}
              </span>
              {showSources ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
            {showSources && (
              <div className="p-2 space-y-1">
                {knowledge.map(k => {
                  const href = attackUrl(k.id);
                  return (
                    <div key={k.id} className="text-[11px] flex items-start gap-2">
                      <span className="text-muted font-mono shrink-0">{k.id}</span>
                      {href ? (
                        <a href={href} target="_blank" rel="noreferrer"
                           className="text-blue-400 hover:text-blue-300 leading-relaxed">
                          {k.title}
                        </a>
                      ) : (
                        <span className="text-primary leading-relaxed">{k.title}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 pt-1 border-t border-border">
          <span className="text-muted text-[10px] uppercase tracking-wider mr-auto">
            {feedback ? `Recorded — thanks` : 'Do you agree?'}
          </span>
          <button
            onClick={() => record(true)}
            disabled={Boolean(feedback)}
            className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] border transition-colors disabled:opacity-50 ${
              feedback === 'agree'
                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                : 'text-muted border-border hover:text-emerald-400 hover:border-emerald-500/40'
            }`}
          >
            <ThumbsUp size={11} /> Agree
          </button>
          <button
            onClick={() => record(false)}
            disabled={Boolean(feedback)}
            className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] border transition-colors disabled:opacity-50 ${
              feedback === 'disagree'
                ? 'bg-red-500/20 text-red-400 border-red-500/40'
                : 'text-muted border-border hover:text-red-400 hover:border-red-500/40'
            }`}
          >
            <ThumbsDown size={11} /> Disagree
          </button>
        </div>
      </div>
    </div>
  );
}
