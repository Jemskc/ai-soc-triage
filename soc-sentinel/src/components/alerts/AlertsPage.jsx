import { useState, useMemo } from 'react';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { severityBg } from '../../utils/severityUtils';
import AlertDetail from './AlertDetail';
import { useAnalysis } from '../../context/AnalysisContext';
import { AICheckedBadge } from '../AnalysisCoverage';

const PAGE_SIZE = 25;
const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/** Present a correlated incident using the same field names the table expects. */
function incidentToRow(incident, verdict) {
  return {
    id: incident.incident_id,
    incident_id: incident.incident_id,
    severity: String(incident.severity || 'low').toUpperCase(),
    timestamp: incident.first_seen,
    rule: incident.rules_fired?.[0]?.rule || 'Correlated incident',
    message:
      verdict?.analyst_summary ||
      `${incident.alert_count} alerts correlated across ${incident.hosts?.length || 0} host(s)`,
    sourceIP: incident.sample_alerts?.[0]?.source_ip || '—',
    user: incident.users?.[0] || '—',
    host: incident.hosts?.[0] || '—',
    status: verdict?.verdict ? verdict.verdict.toLowerCase() : 'open',
    urgency: verdict?.urgency_score ?? null,
    alertCount: incident.alert_count,
  };
}

export default function AlertsPage({ logs, selectedAlert, onSelect, externalQuery = '' }) {
  const [sev, setSev] = useState('ALL');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const { isReady, incidentsByUrgency, verdictFor } = useAnalysis();

  // When a real analysis exists, the list is incidents ordered by AI urgency —
  // the order an analyst should actually work them in. Otherwise it falls back
  // to the raw log rows.
  const rows = useMemo(() => {
    if (!isReady) return logs;
    return incidentsByUrgency.map(inc =>
      incidentToRow(inc, verdictFor(inc.incident_id))
    );
  }, [isReady, incidentsByUrgency, verdictFor, logs]);

  const filtered = useMemo(() => {
    let rows_ = rows;
    if (sev !== 'ALL') rows_ = rows_.filter(l => l.severity === sev);
    // The header search and this panel's own box filter the same list. Before,
    // the header filtered raw logs upstream, which are empty whenever the
    // dashboard is driven by a backend analysis — so searching found nothing.
    const term = (search || externalQuery || '').trim();
    if (term) {
      const q = term.toLowerCase();
      rows_ = rows_.filter(l =>
        l.message?.toLowerCase().includes(q) ||
        l.rule?.toLowerCase().includes(q) ||
        l.sourceIP?.toLowerCase().includes(q) ||
        l.user?.toLowerCase().includes(q) ||
        l.host?.toLowerCase().includes(q)
      );
    }
    return rows_;
  }, [rows, sev, search, externalQuery]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageRows = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  function handleFilter() { setPage(1); }

  return (
    <div className="flex gap-4 h-full animate-fadeIn">
      <div className="flex-1 flex flex-col gap-3 min-w-0">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[180px]">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); handleFilter(); }}
              placeholder="Filter alerts..."
              className="w-full bg-panel border border-border rounded pl-8 pr-3 py-1.5 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>
          <div className="flex gap-1">
            {SEVERITIES.map(s => (
              <button
                key={s}
                onClick={() => { setSev(s); handleFilter(); }}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  sev === s ? 'bg-blue-500 text-white' : 'bg-panel text-muted hover:text-primary border border-border'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <span className="text-muted text-xs">{filtered.length} results</span>
        </div>

        <div className="bg-card border border-border rounded-lg overflow-hidden flex-1 flex flex-col">
          <div className="overflow-auto flex-1">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-card z-10">
                <tr className="border-b border-border">
                  <th className="text-left text-muted px-3 py-2 font-medium">SEV</th>
                  {isReady && <th className="text-left text-muted px-3 py-2 font-medium">AI</th>}
                  {isReady && <th className="text-left text-muted px-3 py-2 font-medium">REVIEWED</th>}
                  <th className="text-left text-muted px-3 py-2 font-medium">TIMESTAMP</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">RULE / MESSAGE</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">SOURCE IP</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">USER</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">HOST</th>
                  <th className="text-left text-muted px-3 py-2 font-medium">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map(log => (
                  <tr
                    key={log.id}
                    onClick={() => onSelect(log)}
                    className={`border-b border-border cursor-pointer transition-colors ${
                      selectedAlert?.id === log.id ? 'bg-hover' : 'hover:bg-hover'
                    }`}
                  >
                    <td className="px-3 py-2">
                      <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${severityBg(log.severity)}`}>
                        {log.severity}
                      </span>
                    </td>
                    {isReady && (
                      <td className="px-3 py-2">
                        {Number.isFinite(log.urgency) ? (
                          <span className={`font-mono tabular-nums text-[11px] ${
                            log.urgency >= 8 ? 'text-red-400'
                              : log.urgency >= 5 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {log.urgency}/10
                          </span>
                        ) : (
                          <span className="text-muted text-[10px]">—</span>
                        )}
                      </td>
                    )}
                    {isReady && (
                      <td className="px-3 py-2">
                        <AICheckedBadge incidentId={log.incident_id} />
                      </td>
                    )}
                    <td className="px-3 py-2 text-muted font-mono whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 max-w-[280px]">
                      <div className="text-primary truncate">{log.rule}</div>
                      <div className="text-muted truncate text-[10px]">{log.message}</div>
                    </td>
                    <td className="px-3 py-2 text-muted font-mono">{log.sourceIP}</td>
                    <td className="px-3 py-2 text-muted">{log.user}</td>
                    <td className="px-3 py-2 text-muted">{log.host}</td>
                    <td className="px-3 py-2">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-hover text-muted capitalize">{log.status}</span>
                    </td>
                  </tr>
                ))}
                {!pageRows.length && (
                  <tr><td colSpan={7} className="px-4 py-8 text-center text-muted">No alerts match the current filters</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="border-t border-border px-4 py-2 flex items-center justify-between">
              <span className="text-muted text-xs">
                Page {page} of {totalPages} ({filtered.length} records)
              </span>
              <div className="flex gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors">
                  <ChevronLeft size={14} />
                </button>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                  className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors">
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {selectedAlert && (
        <div className="w-80 shrink-0">
          <AlertDetail alert={selectedAlert} onClose={() => onSelect(null)} />
        </div>
      )}
    </div>
  );
}
