import { Scale, AlertCircle } from 'lucide-react';

const BAND_STYLES = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/40',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  low: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
};

const ACTION_LABELS = {
  escalate_immediately: 'Escalate immediately',
  analyst_review: 'Analyst review',
  monitor: 'Monitor',
};

/**
 * How the risk score was reached, factor by factor.
 *
 * The score is deterministic arithmetic over the agents' findings, not another
 * model call, so it can be shown as a decomposition. "Why is this a 78?" is a
 * question with an answer here, which is the whole point of scoring this way.
 */
export default function RiskBreakdown({ risk }) {
  if (!risk) return null;

  const band = BAND_STYLES[risk.band] || BAND_STYLES.low;
  const maxPoints = Math.max(...risk.factors.map(f => f.weight), 1);

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <Scale size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">Risk Verdict</span>
        <span className={`ml-auto px-2 py-0.5 rounded border text-[11px] font-semibold ${band}`}>
          {risk.risk_score} · {risk.band}
        </span>
      </div>

      <div className="p-3 space-y-3">
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted text-[10px] uppercase tracking-wider">Action</span>
          <span className="text-primary font-medium">
            {ACTION_LABELS[risk.action] || risk.action}
          </span>
          {risk.requires_approval && (
            <span className="ml-auto px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/40 text-amber-400 text-[10px] font-semibold">
              Needs approval
            </span>
          )}
        </div>

        <div className="space-y-1.5">
          {risk.factors.map(f => (
            <div key={f.name}>
              <div className="flex items-baseline gap-2 text-[11px]">
                <span className="text-primary capitalize">{f.name.replace(/_/g, ' ')}</span>
                <span className="text-muted font-mono ml-auto tabular-nums">
                  {f.points} / {f.weight}
                </span>
              </div>
              <div className="h-1 bg-hover rounded-full overflow-hidden mt-0.5">
                <div
                  className="h-full bg-blue-500 rounded-full"
                  style={{ width: `${(f.points / maxPoints) * 100}%` }}
                />
              </div>
              <p className="text-muted text-[10px] mt-0.5 leading-relaxed">{f.rationale}</p>
            </div>
          ))}
        </div>

        {/* Caveats are part of the verdict, not a footnote. A score built on
            thin evidence or partial telemetry has to say so. */}
        {risk.caveats?.length > 0 && (
          <div className="border-t border-border pt-2 space-y-1">
            {risk.caveats.map((c, i) => (
              <div key={i} className="flex items-start gap-1.5">
                <AlertCircle size={10} className="text-amber-400 mt-0.5 shrink-0" />
                <p className="text-amber-300/90 text-[10px] leading-relaxed">{c}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
