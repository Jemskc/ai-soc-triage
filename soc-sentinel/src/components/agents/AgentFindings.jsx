import { useState } from 'react';
import {
  Bot, Search, BookOpen, Crosshair, ShieldOff, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle2, XCircle, Clock,
} from 'lucide-react';

const AGENT_META = {
  triage:   { icon: Search,    label: 'Triage Agent',   blurb: 'Is this real, and how urgent?' },
  intel:    { icon: BookOpen,  label: 'Intel Agent',    blurb: 'What is it, what comes next?' },
  hunt:     { icon: Crosshair, label: 'Hunt Agent',     blurb: 'What did the rules miss?' },
  response: { icon: ShieldOff, label: 'Response Agent', blurb: 'What do we do about it?' },
};

const SEVERITY_DOT = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500',
  low: 'bg-emerald-500', info: 'bg-slate-500',
};

function AgentCard({ name, result }) {
  const [open, setOpen] = useState(name === 'triage');
  const meta = AGENT_META[name] || { icon: Bot, label: name, blurb: '' };
  const Icon = meta.icon;

  return (
    <div className="border border-border rounded overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 bg-panel hover:bg-hover transition-colors"
      >
        <Icon size={13} className="text-blue-400 shrink-0" />
        <span className="text-primary text-xs font-medium">{meta.label}</span>
        <span className="text-muted text-[10px] hidden sm:inline">{meta.blurb}</span>

        <div className="ml-auto flex items-center gap-2">
          {result.ok
            ? <CheckCircle2 size={11} className="text-emerald-400" />
            : <XCircle size={11} className="text-red-400" />}
          <span className="text-muted text-[10px] font-mono inline-flex items-center gap-1">
            <Clock size={9} />{result.elapsed_seconds}s
          </span>
          {open ? <ChevronUp size={12} className="text-muted" /> : <ChevronDown size={12} className="text-muted" />}
        </div>
      </button>

      {open && (
        <div className="p-3 space-y-2">
          {!result.ok && result.error && (
            <p className="text-red-400 text-[11px]">{result.error}</p>
          )}

          {result.ungrounded?.length > 0 && (
            <div className="flex items-start gap-1.5 p-2 rounded bg-amber-500/10 border border-amber-500/30">
              <AlertTriangle size={11} className="text-amber-400 mt-0.5 shrink-0" />
              <p className="text-amber-300 text-[10px] leading-relaxed">
                Cited {result.ungrounded.join(', ')} without retrieval support — unverified.
              </p>
            </div>
          )}

          {result.findings?.map((f, i) => (
            <div key={i} className="space-y-1.5">
              <div className="flex items-start gap-2">
                <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${SEVERITY_DOT[f.severity] || SEVERITY_DOT.info}`} />
                <p className="text-primary text-[11px] leading-relaxed flex-1">{f.summary}</p>
                {f.confidence > 0 && (
                  <span className="text-muted text-[10px] font-mono shrink-0">
                    {Math.round(f.confidence * 100)}%
                  </span>
                )}
              </div>

              {f.evidence?.length > 0 && (
                <div className="pl-3.5 space-y-1">
                  {f.evidence.slice(0, 4).map((e, j) => (
                    <div key={j} className="text-[10px]">
                      <span className="text-blue-400 font-mono">{e.field}</span>
                      <span className="text-primary font-mono ml-1.5 break-all">
                        {String(e.value ?? '').slice(0, 90)}
                      </span>
                      {e.why && <p className="text-muted leading-relaxed">{e.why}</p>}
                    </div>
                  ))}
                </div>
              )}

              {/* Intel agent's forward-looking view */}
              {f.data?.likely_next_steps?.length > 0 && (
                <div className="pl-3.5">
                  <p className="text-muted text-[10px] uppercase tracking-wider mb-0.5">
                    Likely next adversary steps
                  </p>
                  <ul className="space-y-0.5">
                    {f.data.likely_next_steps.map((s, j) => (
                      <li key={j} className="text-primary text-[10px] leading-relaxed">→ {s}</li>
                    ))}
                  </ul>
                </div>
              )}

              {f.data?.detection_gaps?.length > 0 && (
                <div className="pl-3.5">
                  <p className="text-muted text-[10px] uppercase tracking-wider mb-0.5">
                    Would confirm or rule out
                  </p>
                  <p className="text-muted text-[10px] leading-relaxed">
                    {f.data.detection_gaps.join(' · ')}
                  </p>
                </div>
              )}
            </div>
          ))}

          {result.knowledge_used?.length > 0 && (
            <p className="text-muted text-[10px] pt-1 border-t border-border">
              Grounded in: {result.knowledge_used.map(k => k.id).join(', ')}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/** Every agent's contribution to one case, in the order they ran. */
export default function AgentFindings({ agents }) {
  if (!agents) return null;
  const order = ['intel', 'triage', 'response', 'hunt'];
  const names = order.filter(n => agents[n]);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Bot size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Agent Findings ({names.length} agents)
        </span>
      </div>
      {names.map(n => <AgentCard key={n} name={n} result={agents[n]} />)}
    </div>
  );
}
