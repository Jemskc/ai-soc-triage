import { useState } from 'react';
import {
  Search, Terminal, ChevronDown, ChevronRight, Brain, CheckCircle2,
  AlertTriangle, Clock, Ban, Database, Shield, User, Network, BookOpen,
  History, Activity,
} from 'lucide-react';

const TOOL_META = {
  query_identity:    { icon: User,     label: 'Identity',   tone: 'text-purple-400' },
  query_endpoint:    { icon: Terminal, label: 'Endpoint',   tone: 'text-blue-400' },
  query_network:     { icon: Network,  label: 'Network',    tone: 'text-cyan-400' },
  query_asset:       { icon: Shield,   label: 'Asset',      tone: 'text-amber-400' },
  check_baseline:    { icon: Activity, label: 'Baseline',   tone: 'text-emerald-400' },
  search_knowledge:  { icon: BookOpen, label: 'Knowledge',  tone: 'text-blue-400' },
  timeline:          { icon: Clock,    label: 'Timeline',   tone: 'text-slate-400' },
  find_similar_cases:{ icon: History,  label: 'Precedent',  tone: 'text-indigo-400' },
  conclude:          { icon: CheckCircle2, label: 'Conclude', tone: 'text-emerald-400' },
};

function prettyResult(observation) {
  if (!observation) return null;
  try {
    return JSON.stringify(JSON.parse(observation), null, 1);
  } catch {
    return observation;
  }
}

function Step({ step, isLast }) {
  const [open, setOpen] = useState(false);
  const meta = TOOL_META[step.tool] || { icon: Database, label: step.tool, tone: 'text-muted' };
  const Icon = meta.icon;
  const refused = /already ran|duplicate|deferred/i.test(step.observation || '');
  const failed = Boolean(step.error);

  return (
    <div className="relative pl-7">
      {/* connector */}
      {!isLast && <span className="absolute left-[11px] top-6 bottom-0 w-px bg-border" />}
      <span className={`absolute left-0 top-1 w-[22px] h-[22px] rounded-full border flex items-center justify-center ${
        failed ? 'border-red-500/50 bg-red-500/10'
          : refused ? 'border-amber-500/50 bg-amber-500/10'
          : 'border-border bg-panel'
      }`}>
        <Icon size={11} className={failed ? 'text-red-400' : refused ? 'text-amber-400' : meta.tone} />
      </span>

      <div className="pb-4">
        <div className="flex items-baseline gap-2 flex-wrap">
          <span className="text-muted text-[10px] font-mono">{step.step}</span>
          <span className="text-primary text-xs font-medium">{meta.label}</span>
          {step.args && Object.keys(step.args).length > 0 && (
            <code className="text-[10px] text-muted font-mono">
              {Object.entries(step.args).map(([k, v]) => `${k}=${v}`).join(' ')}
            </code>
          )}
          {step.elapsed_seconds > 0 && (
            <span className="text-muted text-[10px] ml-auto">{step.elapsed_seconds}s</span>
          )}
        </div>

        {/* The reasoning is the point: it shows why this question followed the
            previous answer, which is what separates an investigation from a
            fixed sequence of lookups. */}
        {step.thought && (
          <p className="text-muted text-[11px] leading-relaxed mt-1 italic">
            {step.thought}
          </p>
        )}

        {refused && (
          <p className="text-amber-300/90 text-[10px] mt-1 inline-flex items-start gap-1">
            <Ban size={10} className="mt-0.5 shrink-0" />
            {step.observation}
          </p>
        )}

        {!refused && step.observation && (
          <>
            <button
              onClick={() => setOpen(o => !o)}
              className="mt-1 inline-flex items-center gap-1 text-[10px] text-muted hover:text-primary transition-colors"
            >
              {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
              {open ? 'hide' : 'show'} what came back
            </button>
            {open && (
              <pre className="mt-1 p-2 rounded bg-base border border-border text-[10px] text-primary font-mono overflow-x-auto max-h-52 overflow-y-auto">
                {prettyResult(step.observation)}
              </pre>
            )}
          </>
        )}

        {failed && (
          <p className="text-red-400 text-[10px] mt-1">{step.error}</p>
        )}
      </div>
    </div>
  );
}

const BAND_STYLE = {
  auto_close:  'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  auto_enrich: 'bg-blue-500/15 text-blue-400 border-blue-500/40',
  escalate:    'bg-red-500/15 text-red-400 border-red-500/40',
  hold_for_human: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
};

/**
 * The agent's investigation, step by step.
 *
 * This is the audit trail rendered. A verdict nobody can reconstruct is
 * worthless in a regulated environment, so every tool call, its arguments, the
 * reasoning behind it and what came back are all shown — including the steps
 * that were refused and the ones that found nothing.
 */
export default function InvestigationTrace({ investigation, autonomy, live = false }) {
  if (!investigation) return null;

  const steps = investigation.steps || [];
  const verdict = investigation.verdict || {};
  const incomplete = verdict.incomplete || !investigation.complete;

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <Search size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Agent Investigation
        </span>
        {live && (
          <span className="inline-flex items-center gap-1 text-[10px] text-blue-400">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
            running
          </span>
        )}
        <div className="ml-auto flex items-center gap-2 text-[10px] text-muted">
          <span>{steps.length} steps</span>
          {investigation.elapsed_seconds > 0 && <span>{investigation.elapsed_seconds}s</span>}
          {investigation.parse_failures > 0 && (
            <span className="text-amber-400">{investigation.parse_failures} parse fail</span>
          )}
        </div>
      </div>

      {autonomy && (
        <div className="px-3 py-2 border-b border-border flex items-center gap-2 flex-wrap">
          <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold ${
            BAND_STYLE[autonomy.band] || BAND_STYLE.auto_enrich
          }`}>
            {String(autonomy.band || '').replace(/_/g, ' ')}
          </span>
          {autonomy.reasons?.[0] && (
            <span className="text-muted text-[10px] leading-relaxed flex-1 min-w-0">
              {autonomy.reasons[0]}
            </span>
          )}
          {autonomy.overrides_applied?.length > 0 && (
            <span className="text-amber-300/90 text-[10px] inline-flex items-center gap-1">
              <AlertTriangle size={10} />
              {autonomy.overrides_applied[0]}
            </span>
          )}
        </div>
      )}

      <div className="p-3">
        {steps.length === 0 ? (
          <p className="text-muted text-xs">No investigation recorded for this case.</p>
        ) : (
          steps.map((s, i) => <Step key={i} step={s} isLast={i === steps.length - 1} />)
        )}
      </div>

      {verdict.verdict && (
        <div className="px-3 py-2.5 border-t border-border bg-panel space-y-1.5">
          <div className="flex items-center gap-2">
            <Brain size={12} className="text-blue-400" />
            <span className="text-primary text-xs font-medium">{verdict.verdict}</span>
            {Number.isFinite(verdict.urgency_score) && (
              <span className="text-muted text-[10px]">urgency {verdict.urgency_score}/10</span>
            )}
            {Number.isFinite(verdict.confidence) && (
              <span className="text-muted text-[10px]">
                confidence {Math.round(verdict.confidence * 100)}%
              </span>
            )}
            {incomplete && (
              <span className="ml-auto text-amber-400 text-[10px] inline-flex items-center gap-1">
                <AlertTriangle size={10} /> incomplete — needs an analyst
              </span>
            )}
          </div>
          {verdict.analyst_summary && (
            <p className="text-primary text-[11px] leading-relaxed">{verdict.analyst_summary}</p>
          )}
          {verdict.business_impact && (
            <p className="text-muted text-[11px] leading-relaxed">
              <span className="uppercase tracking-wider text-[9px]">Impact: </span>
              {verdict.business_impact}
            </p>
          )}
          {investigation.stopped_reason && investigation.stopped_reason !== 'concluded' && (
            <p className="text-amber-300/90 text-[10px]">
              Stopped: {investigation.stopped_reason}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
