import { Brain, Check, Loader, AlertTriangle, FlaskConical } from 'lucide-react';
import { useAnalysis } from '../context/AnalysisContext';
import AnalysisCoverage from './AnalysisCoverage';

const STAGE_LABELS = {
  normalize: 'Normalizing events',
  detect: 'Running detection rules',
  correlate: 'Correlating into incidents',
  triage: 'AI triaging incidents',
  campaign: 'Cross-incident analysis',
  fanout: 'Assembling dashboard',
};

const STAGE_ORDER = ['normalize', 'detect', 'correlate', 'triage', 'campaign', 'fanout'];

/**
 * Shows the analysis pipeline working, stage by stage.
 *
 * This is deliberately not a spinner. The interesting claim the product makes
 * is that thousands of raw events collapse into a few dozen incidents an
 * analyst can actually read, and that only happens if you can watch it happen.
 */
export function AnalysisProgressPanel() {
  const { job, isRunning } = useAnalysis();
  if (!isRunning || !job) return null;

  const currentIndex = STAGE_ORDER.indexOf(job.stage);
  const counts = job.counts || {};

  return (
    <div className="fixed inset-0 bg-base/95 flex items-center justify-center z-50 animate-fadeIn">
      <div className="w-full max-w-md space-y-5 px-6">
        <div className="flex items-center gap-2.5">
          <Brain size={20} className="text-blue-400 animate-pulse" />
          <div>
            <p className="text-primary text-sm font-medium">Analyzing your logs</p>
            <p className="text-muted text-xs">{job.message}</p>
          </div>
          <span className="ml-auto text-primary text-lg font-mono tabular-nums">
            {Math.round(job.percent)}%
          </span>
        </div>

        <div className="h-1.5 bg-hover rounded-full overflow-hidden">
          <div
            className="h-full bg-blue-500 rounded-full transition-all duration-500"
            style={{ width: `${job.percent}%` }}
          />
        </div>

        <div className="space-y-1.5">
          {STAGE_ORDER.map((stage, i) => {
            const done = i < currentIndex;
            const active = i === currentIndex;
            return (
              <div
                key={stage}
                className={`flex items-center gap-2 text-xs ${
                  active ? 'text-primary' : done ? 'text-muted' : 'text-muted/50'
                }`}
              >
                <span className="w-4 shrink-0">
                  {done ? <Check size={12} className="text-emerald-400" />
                        : active ? <Loader size={12} className="animate-spin text-blue-400" />
                        : <span className="block w-1 h-1 rounded-full bg-current ml-1.5" />}
                </span>
                {STAGE_LABELS[stage]}
              </div>
            );
          })}
        </div>

        {/* The funnel is the story: this many events became this many incidents. */}
        {(counts.events || counts.alerts || counts.incidents) && (
          <div className="flex items-center justify-between text-xs pt-3 border-t border-border">
            {[
              ['events', 'events'],
              ['alerts', 'rule alerts'],
              ['incidents', 'incidents'],
            ].map(([key, label]) => (
              <div key={key} className="text-center flex-1">
                <p className="text-primary font-mono text-base tabular-nums">
                  {(counts[key] ?? 0).toLocaleString()}
                </p>
                <p className="text-muted text-[10px] uppercase tracking-wider">{label}</p>
              </div>
            ))}
          </div>
        )}

        {job.elapsed_seconds > 0 && (
          <p className="text-muted text-[10px] text-center">
            {Math.round(job.elapsed_seconds)}s elapsed — running locally, no data leaves this machine
          </p>
        )}
      </div>
    </div>
  );
}

/**
 * Persistent banner stating where the data on screen came from.
 *
 * Mock data must never be mistaken for a real analysis run, so the fallback
 * says so plainly rather than failing quietly into something that looks real.
 */
export function DataSourceBadge() {
  const { status, isDemoData, metrics, error } = useAnalysis();

  if (isDemoData) {
    return (
      <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10">
        <FlaskConical size={11} className="text-amber-400" />
        <span className="text-amber-300 text-[10px] font-semibold uppercase tracking-wider">
          Demo data — no analysis run
        </span>
      </div>
    );
  }

  if (status === 'offline') {
    return (
      <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-red-500/40 bg-red-500/10">
        <AlertTriangle size={11} className="text-red-400" />
        <span className="text-red-300 text-[10px] font-semibold uppercase tracking-wider">
          Backend offline{error ? '' : ''}
        </span>
      </div>
    );
  }

  if (status === 'ready' && metrics) {
    return (
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10">
          <Check size={11} className="text-emerald-400" />
          <span className="text-emerald-300 text-[10px] font-semibold uppercase tracking-wider">
            {metrics.incidents} incidents from {metrics.events_ingested?.toLocaleString()} events
          </span>
        </div>
        <AnalysisCoverage compact />
      </div>
    );
  }

  return null;
}

export default AnalysisProgressPanel;
