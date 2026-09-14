import { useEffect, useState } from 'react';
import { Activity, ArrowRight, Search, Database, Filter, Layers } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import SourcePicker from '../SourcePicker';
import LogsExplorer from '../../pages/LogsExplorer';
import { useLiveEvents, useLiveStats } from '../../hooks/useLiveEvents';

const STAGE_LABEL = {
  stream: 'Parsed & normalised',
  rules: 'Matched a detection rule',
  analytics: 'Carried a behavioural signal',
  promotion: 'Promoted with no rule hit',
  correlation: 'Grouped into incidents',
  ranking: 'Sent to the AI',
};

/** The pipeline, as it happened, in order. */
function Pipeline({ stages, metrics }) {
  if (!stages?.length) return null;
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <Layers size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          What happened to these logs
        </span>
        {metrics?.events_ingested && (
          <span className="ml-auto text-muted text-[10px]">
            {metrics.events_ingested.toLocaleString()} events in
          </span>
        )}
      </div>
      <div className="p-3 space-y-1.5">
        {stages.map((s, i) => (
          <div key={s.name} className="flex items-center gap-2 text-[11px]">
            <span className="text-muted w-4 text-right font-mono">{i + 1}</span>
            <span className="text-primary w-52">{STAGE_LABEL[s.name] || s.name}</span>
            <span className="text-muted font-mono tabular-nums">
              {(s.in ?? 0).toLocaleString()}
            </span>
            <ArrowRight size={10} className="text-muted" />
            <span className="text-primary font-mono tabular-nums">
              {(s.out ?? 0).toLocaleString()}
            </span>
          </div>
        ))}
        <p className="text-muted text-[10px] pt-1.5 border-t border-border leading-relaxed">
          Rules and behaviour analysis run on every event. Only the highest-ranked
          incidents reach the AI — a model on every log line would take hours.
        </p>
      </div>
    </div>
  );
}

/**
 * Everything that came in, and what the pipeline made of it.
 *
 * Raw logs stay browsable in full: an analyst checking the AI's work needs the
 * original record, not the platform's summary of it.
 */
export default function LiveLogs({ onSelectLog, onInvestigate, searchQuery }) {
  const { events, metrics, eventTotal, isReady, queryEvents } = useAnalysis();
  const { events: liveEvents, connected } = useLiveEvents();
  const stats = useLiveStats(liveEvents);
  const [showPipeline, setShowPipeline] = useState(true);

  // One page in memory, never the corpus. A real estate produces more events
  // in a day than a browser can hold, so the server filters and pages and this
  // holds only what is on screen.
  const [page, setPage] = useState({ events: [], total: 0, offset: 0, loading: true });
  const [filters, setFilters] = useState({ q: searchQuery || '', severity: '', host: '', user: '', source: '', eventId: '', timeFrom: '', timeTo: '' });
  const [offset, setOffset] = useState(0);
  const PAGE = 500;

  useEffect(() => { setOffset(0); }, [filters.q, filters.severity, filters.host, filters.user, filters.source, filters.eventId, filters.timeFrom, filters.timeTo]);
  useEffect(() => { setFilters(f => ({ ...f, q: searchQuery || '' })); }, [searchQuery]);

  useEffect(() => {
    let cancelled = false;
    setPage(p => ({ ...p, loading: true }));
    queryEvents({ offset, limit: PAGE, ...filters })
      .then(r => {
        if (cancelled) return;
        setPage({
          events: r.events || [],
          total: r.total ?? 0,
          totalUnfiltered: r.total_unfiltered ?? r.total ?? 0,
          offset,
          loading: false,
        });
      })
      .catch(() => { if (!cancelled) setPage(p => ({ ...p, loading: false })); });
    return () => { cancelled = true; };
    // eventTotal is included so the page re-queries when the server's count
    // changes. Without it a view that mounted while the corpus was empty never
    // asked again, and Live Logs stayed blank through an entire import.
  }, [offset, filters, queryEvents, eventTotal]);

  return (
    <div className="flex flex-col gap-3 h-full">
      {showPipeline && (
        <div className="relative">
          <Pipeline stages={stats.stages} metrics={metrics} />
          <button
            onClick={() => setShowPipeline(false)}
            className="absolute top-2 right-3 text-muted hover:text-primary text-[10px]"
          >
            hide
          </button>
        </div>
      )}
      {!showPipeline && (
        <button
          onClick={() => setShowPipeline(true)}
          className="self-start inline-flex items-center gap-1.5 px-2 py-1 rounded border border-border text-muted hover:text-primary text-[10px]"
        >
          <Layers size={10} /> show pipeline
        </button>
      )}

      {connected && (
        <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 self-start">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          live — {(eventTotal || 0).toLocaleString()} events indexed
        </span>
      )}

      {/* The full search surface: natural-language AI search, field queries,
          time range, source and severity filters, export. Raw records stay one
          click away — an analyst checking the AI's work needs the original,
          not the platform's summary of it. */}
      {/* Which files are loaded, and which one is in view. */}
      <SourcePicker
        selected={filters.source}
        onSelect={name => setFilters(f => ({ ...f, source: name }))}
      />

      <div className="flex-1 min-h-0">
        <LogsExplorer
          logs={page.events}
          serverPaged={{
            total: page.total,
            totalUnfiltered: page.totalUnfiltered,
            offset: page.offset,
            pageSize: PAGE,
            loading: page.loading,
            filters,
            onFilter: next => setFilters(f => ({ ...f, ...next })),
            onPage: delta => setOffset(o => Math.max(0, o + delta * PAGE)),
          }}
          onSelectLog={onSelectLog}
          onInvestigate={onInvestigate}
          initialQuery={searchQuery}
        />
      </div>
    </div>
  );
}


