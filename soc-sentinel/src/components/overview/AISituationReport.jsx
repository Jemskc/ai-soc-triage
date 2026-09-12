import { Brain, Target, Radius, ArrowRight, Link2, Loader, Server } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

/**
 * Facts derived straight from the incidents, with no model involved.
 *
 * The AI narrative is campaign-scope: it runs once, after every case is
 * triaged. Rendering nothing until then is indistinguishable from a broken
 * tab, so the deterministic picture stands in — it is genuinely useful, and it
 * is honest about what is still generating.
 */
function DerivedSummary({ incidents, verdicts, metrics, inProgress }) {
  const hosts = new Set();
  const users = new Set();
  const techniques = new Map();
  let escalated = 0;
  let topIncident = null;

  incidents.forEach(inc => {
    (inc.hosts || []).forEach(h => hosts.add(h));
    (inc.users || []).forEach(u => users.add(u));
    (inc.techniques_suspected || []).forEach(t => {
      if (t.technique) techniques.set(t.technique, (techniques.get(t.technique) || 0) + t.count);
    });
    const risk = verdicts[inc.incident_id]?.risk;
    if (risk && (!topIncident || risk.risk_score > topIncident.score)) {
      topIncident = { id: inc.incident_id, score: risk.risk_score, band: risk.band };
    }
    if (String(verdicts[inc.incident_id]?.payload?.verdict || '').toUpperCase() === 'ESCALATE') {
      escalated += 1;
    }
  });

  const topTechniques = [...techniques.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
        {inProgress
          ? <Loader size={14} className="text-blue-400 animate-spin" />
          : <Server size={14} className="text-blue-400" />}
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Situation — derived from the analysis
        </span>
        {inProgress && (
          <span className="ml-auto text-muted text-[10px]">
            AI narrative generates once every case is triaged
          </span>
        )}
      </div>

      <div className="p-4 space-y-3">
        <p className="text-primary text-sm leading-relaxed">
          {incidents.length} correlated incident{incidents.length === 1 ? '' : 's'} across{' '}
          {hosts.size} host{hosts.size === 1 ? '' : 's'} and {users.size} account
          {users.size === 1 ? '' : 's'}
          {metrics?.events_ingested
            ? `, from ${metrics.events_ingested.toLocaleString()} events.`
            : '.'}
          {escalated > 0 && ` ${escalated} escalated by the triage agent.`}
        </p>

        {topIncident && (
          <p className="text-muted text-xs">
            Highest fused risk:{' '}
            <span className="text-primary font-mono">{topIncident.id}</span>{' '}
            at <span className="text-primary">{topIncident.score}</span> ({topIncident.band}).
          </p>
        )}

        {topTechniques.length > 0 && (
          <div>
            <p className="text-muted text-[10px] uppercase tracking-wider mb-1.5">
              Most frequent techniques
            </p>
            <div className="flex flex-wrap gap-1.5">
              {topTechniques.map(([t, n]) => (
                <span key={t} className="px-1.5 py-0.5 rounded bg-panel text-primary text-[10px] font-mono">
                  {t} ×{n}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The Overview headline, written by the AI across all incidents.
 *
 * An analyst walking in does not need four counters; they need to know what is
 * happening and what to touch first. The counters stay, demoted below this.
 */
export default function AISituationReport({ onSelectIncident }) {
  const { campaign, isReady, incidents, verdicts, metrics, bundle } = useAnalysis();
  const report = campaign?.overview?.payload;

  if (!isReady) return null;

  // The AI narrative only exists once the whole run completes. Until then show
  // the deterministic picture rather than an empty tab.
  if (!report) {
    if (!incidents.length) return null;
    return (
      <DerivedSummary
        incidents={incidents}
        verdicts={verdicts}
        metrics={metrics}
        inProgress={Boolean(bundle?.in_progress)}
      />
    );
  }

  const priorities = Array.isArray(report.top_priorities) ? report.top_priorities : [];
  const blast = report.blast_radius || {};
  const confidence = Number.isFinite(report.confidence)
    ? Math.round(report.confidence * 100)
    : null;

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
        <Brain size={14} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          AI Situation Report
        </span>
        <div className="ml-auto flex items-center gap-3">
          {report.is_single_campaign && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/15 border border-red-500/40 text-red-400 text-[10px] font-semibold">
              <Link2 size={10} />
              Single campaign
            </span>
          )}
          {confidence !== null && (
            <span className="text-muted text-[10px]">confidence {confidence}%</span>
          )}
        </div>
      </div>

      <div className="p-4 space-y-4">
        {report.headline && (
          <p className="text-primary text-sm font-medium leading-relaxed">
            {report.headline}
          </p>
        )}

        {report.campaign_narrative && (
          <p className="text-muted text-xs leading-relaxed">{report.campaign_narrative}</p>
        )}

        {priorities.length > 0 && (
          <div>
            <div className="flex items-center gap-1.5 mb-2">
              <Target size={11} className="text-muted" />
              <span className="text-muted text-[10px] uppercase tracking-wider">
                Deal with these first
              </span>
            </div>
            <div className="space-y-1.5">
              {priorities.map((p, i) => (
                <button
                  key={i}
                  onClick={() => onSelectIncident?.(p.incident_id)}
                  className="w-full text-left bg-panel hover:bg-hover rounded p-2.5 transition-colors group"
                >
                  <div className="flex items-start gap-2">
                    <span className="text-muted font-mono text-[11px] shrink-0 mt-0.5">
                      {i + 1}.
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-primary text-xs leading-relaxed">{p.why}</p>
                      {p.action && (
                        <p className="text-blue-400 text-[11px] mt-1 leading-relaxed">
                          → {p.action}
                        </p>
                      )}
                      {p.incident_id && (
                        <span className="text-muted text-[10px] font-mono">
                          {p.incident_id}
                        </span>
                      )}
                    </div>
                    <ArrowRight
                      size={12}
                      className="text-muted opacity-0 group-hover:opacity-100 transition-opacity shrink-0 mt-0.5"
                    />
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {(blast.assessment || blast.hosts?.length || blast.users?.length) && (
          <div className="border-t border-border pt-3">
            <div className="flex items-center gap-1.5 mb-1.5">
              <Radius size={11} className="text-muted" />
              <span className="text-muted text-[10px] uppercase tracking-wider">
                Blast radius
              </span>
            </div>
            {blast.assessment && (
              <p className="text-primary text-xs leading-relaxed mb-2">{blast.assessment}</p>
            )}
            <div className="flex flex-wrap gap-1.5">
              {(blast.hosts || []).slice(0, 8).map(h => (
                <span key={h} className="px-1.5 py-0.5 rounded bg-panel text-primary text-[10px] font-mono">
                  {h}
                </span>
              ))}
              {(blast.users || []).slice(0, 8).map(u => (
                <span key={u} className="px-1.5 py-0.5 rounded bg-panel text-purple-400 text-[10px] font-mono">
                  {u}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
