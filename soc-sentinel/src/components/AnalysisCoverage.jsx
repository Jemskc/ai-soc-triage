import { CheckCircle2, Circle, MinusCircle, Info, Eye } from 'lucide-react';
import { useAnalysis } from '../context/AnalysisContext';

/**
 * "Has the AI actually looked at this?" — answered in plain language.
 *
 * The uncomfortable truth this component exists to state: the AI does not read
 * every log, and it never will. Thousands of events become a few dozen
 * incidents, and only the highest-ranked of those reach a model. That is the
 * design — running a model per log line is unaffordable — but a dashboard that
 * doesn't say so lets a reader assume everything was reviewed.
 *
 * So the chain is shown end to end, including the part that was NOT
 * investigated, in words someone with no security background can follow.
 */
export default function AnalysisCoverage({ compact = false }) {
  const { metrics, bundle, incidents, verdicts, eventTotal, isReady } = useAnalysis();
  if (!isReady) return null;

  const totalEvents = metrics?.events_ingested ?? eventTotal ?? 0;
  const flagged = metrics?.rule_alerts ?? bundle?.counts?.alerts ?? 0;
  const incidentCount = incidents.length;
  const investigated = Object.values(verdicts).filter(v => v?.payload).length;
  const notInvestigated = Math.max(0, incidentCount - investigated);

  if (compact) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[10px]">
        <Eye size={11} className="text-blue-400" />
        <span className="text-muted">
          AI reviewed <span className="text-primary font-medium">{investigated}</span> of{' '}
          {incidentCount} incidents from {totalEvents.toLocaleString()} logs
        </span>
      </span>
    );
  }

  const rows = [
    {
      icon: CheckCircle2, tone: 'text-slate-400',
      value: totalEvents,
      label: 'logs collected',
      plain: 'Everything that came in. All of it is searchable in Logs Explorer.',
    },
    {
      icon: CheckCircle2, tone: 'text-slate-400',
      value: flagged,
      label: 'looked unusual',
      plain: 'Picked out automatically by detection rules and behaviour analysis. No AI yet — this part is fast and runs on everything.',
    },
    {
      icon: CheckCircle2, tone: 'text-blue-400',
      value: incidentCount,
      label: 'grouped into incidents',
      plain: 'Related events joined together, so one intrusion is one case rather than forty separate alerts.',
    },
    {
      icon: CheckCircle2, tone: 'text-emerald-400',
      value: investigated,
      label: 'investigated by the AI',
      plain: 'The AI ran a full investigation on these — you can open any one and read every step it took.',
      strong: true,
    },
    {
      icon: notInvestigated > 0 ? MinusCircle : Circle,
      tone: notInvestigated > 0 ? 'text-amber-400' : 'text-muted',
      value: notInvestigated,
      label: 'not investigated by the AI',
      plain: notInvestigated > 0
        ? 'Ranked below the others and not sent to the AI. They are recorded and can be reviewed, but no AI has read them.'
        : 'Nothing was left out.',
    },
  ];

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
        <Eye size={14} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          What the AI has actually looked at
        </span>
      </div>

      <div className="p-4 space-y-3">
        {rows.map(({ icon: Icon, tone, value, label, plain, strong }) => (
          <div key={label} className="flex items-start gap-3">
            <Icon size={14} className={`${tone} mt-0.5 shrink-0`} />
            <div className="min-w-0">
              <p className={strong ? 'text-primary text-sm font-medium' : 'text-primary text-sm'}>
                <span className="font-mono tabular-nums">{value.toLocaleString()}</span>{' '}
                {label}
              </p>
              <p className="text-muted text-[11px] leading-relaxed mt-0.5">{plain}</p>
            </div>
          </div>
        ))}

        <div className="flex items-start gap-2 pt-2 border-t border-border">
          <Info size={11} className="text-muted mt-0.5 shrink-0" />
          <p className="text-muted text-[10px] leading-relaxed">
            The AI does not read every log, and no system does — it would take
            days per batch. Rules and behaviour analysis run across everything
            first; the AI investigates what those surface as most likely to
            matter. Anything it did not investigate is listed above rather than
            hidden.
          </p>
        </div>
      </div>
    </div>
  );
}

/**
 * Per-row answer to the same question, for tables.
 * Three states, deliberately distinguishable at a glance.
 */
export function AICheckedBadge({ incidentId, size = 'sm' }) {
  const { verdicts, cases } = useAnalysis();
  const record = verdicts[incidentId];
  const investigated = Boolean(cases?.[incidentId]?.agents || record?.payload);
  const pad = size === 'sm' ? 'px-1.5 py-0.5 text-[9px]' : 'px-2 py-0.5 text-[10px]';

  if (investigated) {
    return (
      <span className={`inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 font-medium ${pad}`}>
        <CheckCircle2 size={9} /> AI checked
      </span>
    );
  }
  if (record) {
    return (
      <span className={`inline-flex items-center gap-1 rounded border border-blue-500/40 bg-blue-500/10 text-blue-400 ${pad}`}>
        <Circle size={9} /> queued
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center gap-1 rounded border border-border text-muted ${pad}`}>
      <MinusCircle size={9} /> not checked
    </span>
  );
}
