import { useState, useMemo } from 'react';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { severityBg } from '../../utils/severityUtils';
import AlertDetail from './AlertDetail';

const PAGE_SIZE = 25;
const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function AlertsPage({ logs, selectedAlert, onSelect }) {
  const [sev, setSev] = useState('ALL');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);

  const filtered = useMemo(() => {
    let rows = logs;
    if (sev !== 'ALL') rows = rows.filter(l => l.severity === sev);
    if (search.trim()) {
      const q = search.toLowerCase();
      rows = rows.filter(l =>
        l.message?.toLowerCase().includes(q) ||
        l.rule?.toLowerCase().includes(q) ||
        l.sourceIP?.toLowerCase().includes(q) ||
        l.user?.toLowerCase().includes(q) ||
        l.host?.toLowerCase().includes(q)
      );
    }
    return rows;
  }, [logs, sev, search]);

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
