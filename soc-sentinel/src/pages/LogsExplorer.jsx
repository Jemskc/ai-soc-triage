import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { Search, Play, Bookmark, X, ChevronLeft, ChevronRight, Clock, ChevronDown,
         Copy, Download, Send, Sparkles } from 'lucide-react';
import { severityBg, severityOrder } from '../utils/severityUtils';
import { parseQuery } from '../utils/queryParser';
import { aiLogSearch } from '../utils/aiLogSearch';
import { exportCSV } from '../utils/logExporter';
import { api } from '../utils/api';

const PAGE_SIZE = 50;

const TIME_RANGES = [
  { label: 'Last 15m', ms: 15 * 60_000 },
  { label: 'Last 1h',  ms: 60 * 60_000 },
  { label: 'Last 6h',  ms: 6 * 3600_000 },
  { label: 'Last 24h', ms: 24 * 3600_000 },
  { label: 'Last 7d',  ms: 7 * 86400_000 },
  { label: 'All Time', ms: 0 },
];

const EXAMPLE_CHIPS = [
  'Failed logins last hour',
  'Traffic from 192.168.1.45',
  'PowerShell execution events',
  'Critical alerts this morning',
  'What did admin do today?',
  'Suspicious outbound connections',
  'All root logins this week',
  'Brute force attempts',
];

const SEV_COLORS = {
  CRITICAL: { bar: 'bg-red-500',    text: 'text-red-400',    dot: 'bg-red-500' },
  HIGH:     { bar: 'bg-orange-500', text: 'text-orange-400', dot: 'bg-orange-500' },
  MEDIUM:   { bar: 'bg-yellow-500', text: 'text-yellow-500', dot: 'bg-yellow-500' },
  LOW:      { bar: 'bg-blue-500',   text: 'text-blue-400',   dot: 'bg-blue-500' },
};

function filterByTime(logs, ms) {
  if (!ms) return logs;
  const cutoff = Date.now() - ms;
  return logs.filter(l => { const t = new Date(l.timestamp).getTime(); return !isNaN(t) && t >= cutoff; });
}

function syntaxHighlightJson(obj) {
  const { _raw, ...clean } = obj;
  const escaped = JSON.stringify(clean, null, 2)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return escaped.replace(
    /("(?:\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    m => {
      if (/^"/.test(m)) return /:$/.test(m)
        ? `<span style="color:#60a5fa">${m}</span>`
        : `<span style="color:#4ade80">${m}</span>`;
      if (/true|false/.test(m)) return `<span style="color:#fb923c">${m}</span>`;
      if (/null/.test(m))        return `<span style="color:#94a3b8">${m}</span>`;
      return `<span style="color:#facc15">${m}</span>`;
    }
  );
}

// ─── ExpandedRow ─────────────────────────────────────────────────────────────
function ExpandedRow({ log, onPivot, onSendToAI, onFindRelated, onInvestigate }) {
  const [copied, setCopied] = useState(false);
  const [explain, setExplain] = useState(null);
  const [explainState, setExplainState] = useState('idle'); // idle | loading | error
  const [explainError, setExplainError] = useState('');

  // Explains one line through the logs contract: the model is given the event
  // plus knowledge-base chunks retrieved on its event id, process and command
  // line, and may only cite what came back.
  function runExplain() {
    setExplainState('loading');
    setExplain(null);
    api.enrichEvent(log)
      .then(res => {
        if (res.ok && res.payload) { setExplain(res); setExplainState('idle'); }
        else { setExplainError(res.error || 'no valid explanation returned'); setExplainState('error'); }
      })
      .catch(err => { setExplainError(String(err.message || err)); setExplainState('error'); });
  }

  function copyJson() {
    const { _raw, ...rest } = log;
    navigator.clipboard.writeText(JSON.stringify(rest, null, 2))
      .then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); })
      .catch(() => {});
  }

  const isIP  = v => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(v));
  const fields = Object.entries(log).filter(([k]) => k !== '_raw' && k !== 'id');
  const { _raw, ...logForJson } = log;

  return (
    <div className="grid grid-cols-2 gap-5">
      {/* Left: all fields */}
      <div>
        <p className="text-muted text-[10px] uppercase tracking-wider mb-2">All Fields</p>
        <div className="space-y-1 max-h-52 overflow-y-auto pr-1">
          {fields.map(([key, val]) => (
            <div key={key} className="flex items-start gap-2 text-[10px]">
              <span className="text-blue-400 font-mono shrink-0 w-24 truncate">{key}</span>
              <span className="text-primary font-mono break-all flex-1">{String(val ?? '')}</span>
              {isIP(val) && val !== 'Unknown' && (
                <button onClick={() => onPivot('sourceIP', String(val))}
                  className="shrink-0 px-1.5 py-0.5 bg-hover border border-border rounded text-[9px] text-muted hover:text-primary hover:border-blue-500 transition-colors">
                  Search IP
                </button>
              )}
              {key === 'user' && val && val !== 'Unknown' && (
                <button onClick={() => onPivot('user', String(val))}
                  className="shrink-0 px-1.5 py-0.5 bg-hover border border-border rounded text-[9px] text-muted hover:text-primary hover:border-blue-500 transition-colors">
                  Search user
                </button>
              )}
              {key === 'host' && val && val !== 'Unknown' && (
                <button onClick={() => onPivot('host', String(val))}
                  className="shrink-0 px-1.5 py-0.5 bg-hover border border-border rounded text-[9px] text-muted hover:text-primary hover:border-blue-500 transition-colors">
                  Search host
                </button>
              )}
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          <button onClick={() => onSendToAI && onSendToAI(log)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors">
            <Send size={10} /> Send to AI Panel
          </button>
          <button onClick={onFindRelated}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border hover:border-blue-500 rounded text-xs text-primary transition-colors">
            Find Related Events
          </button>
          {onInvestigate && (
            <button onClick={() => onInvestigate(log)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border hover:border-blue-500 rounded text-xs text-primary transition-colors">
              View in Timeline
            </button>
          )}
          <button onClick={runExplain} disabled={explainState === 'loading'}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border hover:border-blue-500 rounded text-xs text-primary transition-colors disabled:opacity-50">
            {explainState === 'loading' ? 'Explaining…' : 'Explain this event'}
          </button>
        </div>

        {(explain || explainState !== 'idle') && (
          <div className="mt-3 bg-panel border border-border rounded p-3 space-y-2">
            {explainState === 'loading' && (
              <p className="text-muted text-[10px]">Retrieving context and explaining…</p>
            )}
            {explainState === 'error' && (
              <p className="text-amber-400 text-[10px]">Could not explain — {explainError}</p>
            )}
            {explain && (
              <>
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                    explain.payload.significance === 'noteworthy' ? 'bg-amber-500/20 text-amber-400'
                    : explain.payload.significance === 'routine' ? 'bg-green-500/20 text-green-400'
                    : 'bg-hover text-muted'}`}>{explain.payload.significance}</span>
                  <span className="text-muted text-[9px]">confidence {explain.payload.confidence}</span>
                  <span className="ml-auto text-muted text-[9px]">{explain.elapsed_seconds}s</span>
                </div>
                <p className="text-primary text-[11px] leading-relaxed">{explain.payload.explanation}</p>
                {explain.payload.benign_explanation && (
                  <p className="text-muted text-[10px] leading-relaxed">
                    <span className="uppercase tracking-wider">Benign baseline</span> — {explain.payload.benign_explanation}
                  </p>
                )}
                {!!(explain.knowledge_used || []).length && (
                  <div className="pt-2 border-t border-border">
                    <p className="text-muted text-[9px] uppercase tracking-wider mb-1">Grounded in</p>
                    {explain.knowledge_used.map(k => (
                      <p key={k.id} className="text-blue-400 text-[9px]">{k.id} — {k.title}</p>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      {/* Right: raw JSON */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <p className="text-muted text-[10px] uppercase tracking-wider">Raw Log</p>
          <button onClick={copyJson}
            className="flex items-center gap-1 px-2 py-0.5 bg-hover border border-border rounded text-[10px] text-muted hover:text-primary transition-colors">
            <Copy size={9} /> {copied ? 'Copied!' : 'Copy JSON'}
          </button>
        </div>
        <pre
          className="text-[10px] bg-panel border border-border rounded p-3 overflow-auto max-h-52 font-mono leading-relaxed"
          dangerouslySetInnerHTML={{ __html: syntaxHighlightJson(logForJson) }}
        />
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function LogsExplorer({ logs, onSelectLog, onInvestigate, initialQuery = '' }) {
  const [searchMode,   setSearchMode]   = useState('ai');
  const [aiQuery,      setAiQuery]      = useState('');
  const [queryInput,   setQueryInput]   = useState('');

  const [aiResult,    setAiResult]    = useState(null);
  const [aiDismissed, setAiDismissed] = useState(false);

  // unified filter list — set by both AI and query mode
  const [activeFilters, setActiveFilters] = useState([]);

  const [timeRange,    setTimeRange]    = useState(TIME_RANGES[5]);
  const [selectedSrcs, setSelectedSrcs] = useState(new Set());
  const [selectedSevs, setSelectedSevs] = useState(new Set());
  const [savedQueries, setSavedQueries] = useState([]);
  const [sortOrder,    setSortOrder]    = useState('newest');
  const [page,         setPage]         = useState(1);
  const [expandedId,   setExpandedId]   = useState(null);
  const [showHistory,  setShowHistory]  = useState(false);
  const [searchHistory, setSearchHistory] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('log-search-history') || '[]'); } catch { return []; }
  });

  // ── Derived data ────────────────────────────────────────────────────────────
  const sources = useMemo(() => {
    if (!logs?.length) return [];
    const c = {};
    for (const l of logs) c[l.source || 'Unknown'] = (c[l.source || 'Unknown'] || 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  }, [logs]);

  const sevCounts = useMemo(() => {
    if (!logs?.length) return {};
    return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, ...Object.fromEntries(
      ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => [s, logs.filter(l => l.severity === s).length])
    )};
  }, [logs]);

  const filtered = useMemo(() => {
    if (!logs?.length) return [];
    let rows = filterByTime(logs, timeRange.ms);

    for (const f of activeFilters) {
      if (f.operator === 'in') {
        const vals = f.value.split('|').map(v => v.toUpperCase());
        rows = rows.filter(l => vals.includes(String(l[f.field] ?? '').toUpperCase()));
      } else if (f.operator === 'contains') {
        rows = rows.filter(l => String(l[f.field] ?? '').toLowerCase().includes(f.value.toLowerCase()));
      } else {
        rows = rows.filter(l => String(l[f.field] ?? '').toLowerCase() === f.value.toLowerCase());
      }
    }
    if (selectedSrcs.size > 0) rows = rows.filter(l => selectedSrcs.has(l.source || 'Unknown'));
    if (selectedSevs.size > 0) rows = rows.filter(l => selectedSevs.has(l.severity));

    const out = [...rows];
    if (sortOrder === 'newest')   out.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    else if (sortOrder === 'oldest')   out.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    else if (sortOrder === 'severity') out.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));
    return out;
  }, [logs, activeFilters, timeRange, selectedSrcs, selectedSevs, sortOrder]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageRows   = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // ── Helpers ─────────────────────────────────────────────────────────────────
  function saveHistory(q) {
    const next = [q, ...searchHistory.filter(h => h !== q)].slice(0, 10);
    setSearchHistory(next);
    sessionStorage.setItem('log-search-history', JSON.stringify(next));
  }

  // A query handed in from another tab — the header search, or a hunting
  // hypothesis clicked through — should populate the box and actually run,
  // rather than being silently dropped.
  useEffect(() => {
    if (!initialQuery) return;
    setSearchMode('ai');
    setAiQuery(initialQuery);
    runAI(initialQuery);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery]);

  function runAI(query) {
    const q = query ?? aiQuery;
    if (!q.trim()) return;
    setAiQuery(q);
    const result = aiLogSearch(q, logs);
    setAiResult(result);
    setAiDismissed(false);
    setActiveFilters(result.filters);
    if (result.suggestedTimeRange) {
      const tr = TIME_RANGES.find(t => t.label === result.suggestedTimeRange.label);
      if (tr) setTimeRange(tr);
    }
    saveHistory(q);
    setPage(1);
    setShowHistory(false);
  }

  function runQuery() {
    const conds = parseQuery(queryInput);
    setActiveFilters(conds.map(c => ({
      field: c.field === 'ip' ? 'sourceIP' : c.field === 'event_id' ? 'rule' : c.field,
      value: c.value,
      operator: c.field === 'message' ? 'contains' : 'equals',
    })));
    setAiResult(null);
    setPage(1);
  }

  function switchToQuery() {
    setSearchMode('query');
    if (aiResult?.translatedQuery) setQueryInput(aiResult.translatedQuery);
  }

  function useChip(text) {
    setSearchMode('ai');
    runAI(text);
  }

  function removeFilter(idx) { setActiveFilters(f => f.filter((_, i) => i !== idx)); setPage(1); }

  function toggleSrc(src) {
    setSelectedSrcs(prev => { const n = new Set(prev); n.has(src) ? n.delete(src) : n.add(src); return n; });
    setPage(1);
  }
  function toggleSev(sev) {
    setSelectedSevs(prev => { const n = new Set(prev); n.has(sev) ? n.delete(sev) : n.add(sev); return n; });
    setPage(1);
  }

  const pivot = useCallback((field, value) => {
    const msgs = {
      sourceIP: `Show all logs from IP ${value}`,
      user: `What did ${value} do in the last 24 hours?`,
      host: `Show all activity on host ${value}`,
    };
    setSearchMode('ai');
    runAI(msgs[field] || `${field}:${value}`);
  }, [logs, timeRange]);

  // ── Empty state ──────────────────────────────────────────────────────────────
  if (!logs?.length) {
    return (
      <div className="flex-1 flex items-center justify-center animate-fadeIn">
        <div className="text-center space-y-2">
          <p className="text-primary font-medium text-sm">No log data available</p>
          <p className="text-muted text-xs">Import a log file from the Overview page to explore logs here.</p>
        </div>
      </div>
    );
  }

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full animate-fadeIn">

      {/* ── LEFT FILTER PANEL ─────────────────────────────────────────────── */}
      <div className="w-[200px] shrink-0 border-r border-border bg-panel flex flex-col overflow-y-auto">
        <div className="px-3 py-3 border-b border-border">
          <p className="text-muted text-[10px] uppercase tracking-wider">Log Sources</p>
        </div>
        <div className="py-1">
          {/* All */}
          <button
            onClick={() => { setSelectedSrcs(new Set()); setPage(1); }}
            className={`w-full flex items-center justify-between px-3 py-2 text-xs transition-colors border-l-2 ${
              selectedSrcs.size === 0
                ? 'border-blue-500 bg-hover text-primary'
                : 'border-transparent text-muted hover:text-primary hover:bg-hover/50'
            }`}
          >
            <span>All</span><span className="text-[10px]">{logs.length}</span>
          </button>
          {sources.map(([src, cnt]) => (
            <button key={src} onClick={() => toggleSrc(src)}
              className={`w-full flex items-center gap-2 px-3 py-2 text-xs transition-colors border-l-2 ${
                selectedSrcs.has(src)
                  ? 'border-blue-500 bg-hover text-primary'
                  : 'border-transparent text-muted hover:text-primary hover:bg-hover/50'
              }`}
            >
              <input type="checkbox" readOnly checked={selectedSrcs.has(src)}
                className="accent-blue-500 w-3 h-3 shrink-0 pointer-events-none" />
              <span className="flex-1 truncate text-left">{src}</span>
              <span className="text-[10px] shrink-0">{cnt}</span>
            </button>
          ))}
        </div>

        {/* Severity breakdown */}
        <div className="px-3 pt-3 pb-2 border-t border-border mt-1">
          <p className="text-muted text-[10px] uppercase tracking-wider mb-2">Severity</p>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => {
            const cnt = sevCounts[sev] || 0;
            const pct = logs.length > 0 ? Math.round((cnt / logs.length) * 100) : 0;
            const c = SEV_COLORS[sev];
            return (
              <button key={sev} onClick={() => toggleSev(sev)}
                className={`w-full flex items-center gap-2 py-1.5 px-2 rounded text-xs transition-colors mb-0.5 ${
                  selectedSevs.has(sev) ? 'bg-hover' : 'hover:bg-hover/50'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${c.dot} shrink-0`} />
                <span className={`${c.text} text-[10px] font-medium w-14 text-left`}>{sev}</span>
                <div className="flex-1 h-1 bg-border rounded overflow-hidden">
                  <div className={`h-full ${c.bar} rounded`} style={{ width: `${pct}%` }} />
                </div>
                <span className="text-[10px] text-muted w-6 text-right">{cnt}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── RIGHT COLUMN ──────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* ── SEARCH ZONE ──────────────────────────────────────────────── */}
        <div className="border-b border-border bg-panel p-3 space-y-2.5 shrink-0">
          {/* Mode pills + time range */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 flex-wrap">
              <button onClick={() => setSearchMode('ai')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                  searchMode === 'ai' ? 'bg-blue-600 text-white' : 'border border-border text-muted hover:text-primary'
                }`}>
                <Sparkles size={11} /> AI Search
              </button>
              <button onClick={switchToQuery}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                  searchMode === 'query' ? 'bg-blue-600 text-white' : 'border border-border text-muted hover:text-primary'
                }`}>
                Query
              </button>
              <span className="text-muted text-[10px] hidden sm:block">
                {searchMode === 'ai'
                  ? 'Ask in plain English — AI will find the logs'
                  : 'Use field:value syntax — source:firewall severity:HIGH'}
              </span>
            </div>
            <select value={timeRange.label}
              onChange={e => { setTimeRange(TIME_RANGES.find(r => r.label === e.target.value)); setPage(1); }}
              className="shrink-0 bg-base border border-border rounded px-2 py-1.5 text-xs text-primary focus:outline-none focus:border-blue-500 cursor-pointer">
              {TIME_RANGES.map(r => <option key={r.label}>{r.label}</option>)}
            </select>
          </div>

          {/* AI mode */}
          {searchMode === 'ai' && (
            <div className="space-y-2">
              <div className="relative">
                <textarea
                  value={aiQuery}
                  onChange={e => setAiQuery(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runAI(); }}
                  rows={3}
                  placeholder={"Describe what you're looking for...\ne.g. 'Show me all failed logins for user admin in the last hour'\ne.g. 'What did john.doe do on host WS-23 yesterday?'"}
                  className="w-full bg-base border border-border rounded px-3 py-2 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 transition-colors resize-none leading-relaxed"
                />
                {searchHistory.length > 0 && (
                  <div className="absolute bottom-2 right-2">
                    <button onClick={() => setShowHistory(p => !p)}
                      className="flex items-center gap-1 text-[10px] text-muted hover:text-primary transition-colors">
                      <Clock size={10} /> Recent <ChevronDown size={8} className={showHistory ? 'rotate-180 transition-transform' : 'transition-transform'} />
                    </button>
                    {showHistory && (
                      <div className="absolute bottom-full right-0 mb-1 w-72 bg-card border border-border rounded-lg shadow-xl z-30 overflow-hidden">
                        <div className="px-3 py-1.5 border-b border-border text-[10px] text-muted uppercase tracking-wider">Recent searches</div>
                        {searchHistory.map((h, i) => (
                          <button key={i} onClick={() => { setShowHistory(false); runAI(h); }}
                            className="w-full text-left px-3 py-2 text-xs text-primary hover:bg-hover transition-colors truncate block">{h}</button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <button onClick={() => runAI()} disabled={!aiQuery.trim()}
                  className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white font-medium transition-colors disabled:opacity-40">
                  <Sparkles size={11} /> Search with AI
                </button>
                <button onClick={() => { setAiQuery(''); setAiResult(null); setActiveFilters([]); setPage(1); }}
                  className="px-3 py-1.5 border border-border rounded text-xs text-muted hover:text-primary transition-colors">
                  Clear
                </button>
                <div className="flex flex-wrap gap-1">
                  {EXAMPLE_CHIPS.map(chip => (
                    <button key={chip} onClick={() => useChip(chip)}
                      className="px-2 py-1 bg-hover border border-border rounded-full text-[10px] text-muted hover:text-primary hover:border-blue-500 transition-colors">
                      {chip}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Query mode */}
          {searchMode === 'query' && (
            <div className="space-y-2">
              <div className="flex gap-2">
                <input value={queryInput} onChange={e => setQueryInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && runQuery()}
                  placeholder="source:windows  severity:CRITICAL  user:admin  ip:192.168.1.45"
                  className="flex-1 bg-base border border-border rounded px-3 py-1.5 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 transition-colors font-mono" />
                <button onClick={runQuery}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors">
                  <Play size={10} /> Run
                </button>
                <button onClick={() => { if (queryInput.trim() && !savedQueries.includes(queryInput.trim())) setSavedQueries(s => [...s, queryInput.trim()]); }}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border hover:border-blue-500 rounded text-xs text-primary transition-colors">
                  <Bookmark size={10} /> Save
                </button>
                <button onClick={() => { setQueryInput(''); setActiveFilters([]); setPage(1); }}
                  className="px-3 py-1.5 border border-border rounded text-xs text-muted hover:text-primary transition-colors">Clear</button>
              </div>
              {savedQueries.length > 0 && (
                <div className="flex flex-wrap gap-1.5 items-center">
                  <span className="text-[10px] text-muted">Saved:</span>
                  {savedQueries.map((q, i) => (
                    <div key={i} className="flex items-center gap-1 bg-hover border border-border rounded px-2 py-0.5">
                      <button onClick={() => { setQueryInput(q); runQuery(); }}
                        className="text-[10px] text-muted hover:text-primary font-mono transition-colors">{q}</button>
                      <button onClick={() => setSavedQueries(s => s.filter((_, j) => j !== i))}
                        className="text-muted hover:text-red-400 transition-colors"><X size={9} /></button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── AI SEARCH RESULT BADGE ────────────────────────────────────── */}
        {aiResult && !aiDismissed && (
          <div className="mx-3 mt-2 shrink-0 flex items-center gap-2 px-3 py-2 rounded-lg border border-blue-500/30 bg-blue-500/5">
            <Sparkles size={11} className="text-blue-400 shrink-0" />
            <span className="text-blue-300 text-xs flex-1">
              Found <span className="font-semibold">{filtered.length.toLocaleString()}</span> logs matching <span className="italic">"{aiQuery}"</span>
            </span>
            {aiResult.translatedQuery && (
              <button onClick={switchToQuery}
                className="font-mono text-[10px] bg-hover border border-border rounded px-2 py-0.5 text-blue-400 hover:border-blue-500 transition-colors shrink-0">
                {aiResult.translatedQuery}
              </button>
            )}
            <button onClick={() => setAiDismissed(true)} className="text-muted hover:text-primary transition-colors shrink-0">
              <X size={11} />
            </button>
          </div>
        )}

        {/* ── META BAR ──────────────────────────────────────────────────── */}
        <div className="px-3 py-2 border-b border-border bg-panel flex items-center gap-2 flex-wrap shrink-0">
          <span className="text-muted text-xs">
            Showing <span className="text-primary font-medium">{filtered.length.toLocaleString()}</span> of{' '}
            <span className="text-primary">{logs.length.toLocaleString()}</span> logs
          </span>
          {activeFilters.map((f, i) => (
            <span key={i} className="flex items-center gap-1 bg-blue-500/15 border border-blue-500/30 rounded px-2 py-0.5 text-[10px] text-blue-400 font-mono">
              {f.field === 'sourceIP' ? 'ip' : f.field}:{f.value}
              <button onClick={() => removeFilter(i)} className="hover:text-blue-200"><X size={9} /></button>
            </span>
          ))}
          {[...selectedSrcs].map(src => (
            <span key={src} className="flex items-center gap-1 bg-green-500/15 border border-green-500/30 rounded px-2 py-0.5 text-[10px] text-green-400 font-mono">
              source:{src}
              <button onClick={() => toggleSrc(src)} className="hover:text-green-200"><X size={9} /></button>
            </span>
          ))}
          {[...selectedSevs].map(sev => (
            <span key={sev} className="flex items-center gap-1 bg-orange-500/15 border border-orange-500/30 rounded px-2 py-0.5 text-[10px] text-orange-400 font-mono">
              severity:{sev}
              <button onClick={() => toggleSev(sev)} className="hover:text-orange-200"><X size={9} /></button>
            </span>
          ))}
          <div className="ml-auto flex items-center gap-2 shrink-0">
            <select value={sortOrder} onChange={e => { setSortOrder(e.target.value); setPage(1); }}
              className="bg-base border border-border rounded px-2 py-1 text-[10px] text-primary focus:outline-none focus:border-blue-500 cursor-pointer">
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
              <option value="severity">Severity (high→low)</option>
            </select>
            <button onClick={() => exportCSV(filtered, 'logs_filtered.csv')}
              className="flex items-center gap-1 px-2 py-1 bg-hover border border-border rounded text-[10px] text-primary hover:border-blue-500 transition-colors">
              <Download size={10} /> Export
            </button>
          </div>
        </div>

        {/* ── LOG TABLE ─────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-auto">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-8">
              <Search size={32} className="text-muted opacity-30" />
              <p className="text-primary font-medium text-sm">No logs matched your search</p>
              <div className="space-y-1 text-xs text-muted">
                <p>Try broadening your time range</p>
                <p>Try different keywords or a less specific query</p>
              </div>
              <button onClick={() => {
                setAiQuery(''); setQueryInput(''); setActiveFilters([]); setAiResult(null);
                setSelectedSrcs(new Set()); setSelectedSevs(new Set()); setTimeRange(TIME_RANGES[5]); setPage(1);
              }} className="px-4 py-2 border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors">
                Clear search and show all logs
              </button>
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-card z-10">
                <tr className="border-b border-border">
                  <th className="text-left text-muted px-2 py-2 font-medium w-8">#</th>
                  <th className="text-left text-muted px-3 py-2 font-medium whitespace-nowrap">Time</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">Source</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">Severity</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">Event Type</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">User</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">Source IP</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">Message</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map((log, idx) => (
                  <>
                    <tr key={log.id}
                      onClick={() => setExpandedId(id => id === log.id ? null : log.id)}
                      className="border-b border-border hover:bg-hover cursor-pointer transition-colors">
                      <td className="px-2 py-2 text-muted text-[10px]">{(page - 1) * PAGE_SIZE + idx + 1}</td>
                      <td className="px-3 py-2 text-muted font-mono whitespace-nowrap text-[10px]">{new Date(log.timestamp).toLocaleString()}</td>
                      <td className="px-3 py-2 text-muted">{log.source}</td>
                      <td className="px-3 py-2">
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${severityBg(log.severity)}`}>{log.severity}</span>
                      </td>
                      <td className="px-3 py-2 text-primary max-w-[130px] truncate">{log.rule}</td>
                      <td className="px-3 py-2 text-muted">{log.user}</td>
                      <td className="px-3 py-2 text-muted font-mono">{log.sourceIP}</td>
                      <td className="px-3 py-2 text-muted max-w-[260px] truncate">
                        {log.message?.slice(0, 90)}{log.message?.length > 90 ? '…' : ''}
                      </td>
                    </tr>
                    {expandedId === log.id && (
                      <tr key={`${log.id}-exp`} className="bg-base border-b border-border">
                        <td colSpan={8} className="px-4 py-4">
                          <ExpandedRow
                            log={log}
                            onPivot={pivot}
                            onSendToAI={onSelectLog}
                            onFindRelated={() => {
                              const q = `Show all events related to user ${log.user} and IP ${log.sourceIP}`;
                              setSearchMode('ai');
                              runAI(q);
                            }}
                            onInvestigate={onInvestigate ? () => onInvestigate(log) : null}
                          />
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* ── PAGINATION ────────────────────────────────────────────────── */}
        {totalPages > 1 && (
          <div className="border-t border-border px-4 py-2 flex items-center justify-between bg-panel shrink-0">
            <span className="text-muted text-xs">Page {page} of {totalPages} ({filtered.length.toLocaleString()} records)</span>
            <div className="flex items-center gap-1">
              <button onClick={() => setPage(1)} disabled={page === 1}
                className="px-2 py-1 text-muted hover:text-primary disabled:opacity-30 transition-colors text-xs">«</button>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors"><ChevronLeft size={14} /></button>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors"><ChevronRight size={14} /></button>
              <button onClick={() => setPage(totalPages)} disabled={page === totalPages}
                className="px-2 py-1 text-muted hover:text-primary disabled:opacity-30 transition-colors text-xs">»</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
