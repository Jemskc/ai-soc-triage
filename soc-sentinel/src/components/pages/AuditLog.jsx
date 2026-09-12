import { useEffect, useState } from 'react';
import {
  FileSearch, Search, ChevronDown, ChevronRight, Shield, Scale,
  AlertTriangle, CheckCircle2, Clock, Download,
} from 'lucide-react';
import { api } from '../../utils/api';
import InvestigationTrace from '../investigation/InvestigationTrace';

const BAND_TONE = {
  auto_close: 'text-emerald-400', auto_enrich: 'text-blue-400',
  escalate: 'text-red-400', hold_for_human: 'text-amber-400',
};

function Entry({ entry }) {
  const [open, setOpen] = useState(false);
  const inv = entry.investigation || {};

  return (
    <div className="border-b border-border last:border-0">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full px-3 py-2.5 hover:bg-hover transition-colors text-left"
      >
        <div className="flex items-center gap-2 flex-wrap">
          {open ? <ChevronDown size={12} className="text-muted shrink-0" />
                : <ChevronRight size={12} className="text-muted shrink-0" />}
          <span className="text-primary text-[11px] font-mono">{entry.incident_id}</span>
          <span className="text-primary text-[11px]">{entry.verdict || '—'}</span>
          {Number.isFinite(entry.risk_score) && (
            <span className="text-muted text-[10px]">risk {entry.risk_score}</span>
          )}
          <span className={`text-[10px] ${BAND_TONE[entry.autonomy_band] || 'text-muted'}`}>
            {String(entry.autonomy_band || '').replace(/_/g, ' ')}
          </span>
          {entry.asset_criticality && entry.asset_criticality !== 'standard' && (
            <span className="text-amber-400 text-[10px] inline-flex items-center gap-1">
              <Shield size={9} /> {entry.asset_criticality.replace(/_/g, ' ')}
            </span>
          )}
          <span className="ml-auto text-muted text-[10px] inline-flex items-center gap-1">
            <Clock size={9} /> {inv.step_count ?? 0} steps
            {inv.elapsed_seconds ? ` · ${inv.elapsed_seconds}s` : ''}
          </span>
          {entry.ungrounded_citations?.length > 0 && (
            <AlertTriangle size={10} className="text-amber-400" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-3">
          {/* Why the score is what it is — the deterministic half. */}
          {entry.risk_factors?.length > 0 && (
            <div className="border border-border rounded p-2.5">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Scale size={11} className="text-blue-400" />
                <span className="text-muted text-[10px] uppercase tracking-wider">
                  Risk factors — deterministic, reproducible
                </span>
              </div>
              {entry.risk_factors.map(f => (
                <div key={f.name} className="flex items-baseline gap-2 text-[10px]">
                  <span className="text-primary capitalize w-32 shrink-0">
                    {f.name.replace(/_/g, ' ')}
                  </span>
                  <span className="text-muted font-mono">{f.points}/{f.weight}</span>
                  <span className="text-muted leading-relaxed">{f.rationale}</span>
                </div>
              ))}
            </div>
          )}

          {/* Why the agent was or wasn't allowed to act alone. */}
          {entry.autonomy_reasons?.length > 0 && (
            <div className="border border-border rounded p-2.5">
              <span className="text-muted text-[10px] uppercase tracking-wider">
                Policy decision
              </span>
              {entry.autonomy_reasons.map((r, i) => (
                <p key={i} className="text-primary text-[11px] leading-relaxed mt-1">{r}</p>
              ))}
              {entry.autonomy_overrides?.map((o, i) => (
                <p key={i} className="text-amber-300/90 text-[10px] mt-1 inline-flex items-start gap-1">
                  <AlertTriangle size={9} className="mt-0.5 shrink-0" /> {o}
                </p>
              ))}
              <p className="text-muted text-[10px] mt-1">
                Approval required: {entry.required_approval ? 'yes' : 'no'}
              </p>
            </div>
          )}

          {/* The full reconstruction. */}
          {inv.steps?.length > 0 && (
            <InvestigationTrace
              investigation={inv}
              autonomy={{
                band: entry.autonomy_band,
                reasons: entry.autonomy_reasons,
                overrides_applied: entry.autonomy_overrides,
              }}
            />
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Every AI decision, reconstructable.
 *
 * Exists because a verdict nobody can reproduce is worthless in a regulated
 * environment — and because "the AI decided" is not an answer an auditor,
 * a regulator or an analyst who disagrees will accept. Each row expands into
 * the deterministic risk arithmetic, the policy band and why it applied, and
 * every tool the agent called with what came back.
 */
export default function AuditLog() {
  const [entries, setEntries] = useState(null);
  const [query, setQuery] = useState('');
  const [band, setBand] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    api.audit({ q: query || undefined, band: band || undefined })
      .then(d => !cancelled && (d.error ? setError(d.error) : setEntries(d)))
      .catch(e => !cancelled && setError(e.message));
    return () => { cancelled = true; };
  }, [query, band]);

  function exportJson() {
    const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-audit-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (error) {
    return <p className="text-muted text-xs">Audit log unavailable: {error}</p>;
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search decisions, hosts, accounts, tools used…"
            className="w-full bg-panel border border-border rounded pl-8 pr-3 py-1.5 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500"
          />
        </div>
        <select
          value={band}
          onChange={e => setBand(e.target.value)}
          className="bg-panel border border-border rounded px-2 py-1.5 text-xs text-primary focus:outline-none focus:border-blue-500"
        >
          <option value="">All bands</option>
          <option value="auto_close">Auto-closed</option>
          <option value="auto_enrich">Analyst review</option>
          <option value="escalate">Escalated</option>
          <option value="hold_for_human">Held for human</option>
        </select>
        <button
          onClick={exportJson}
          disabled={!entries?.entries?.length}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-border text-muted hover:text-primary text-xs transition-colors disabled:opacity-40"
        >
          <Download size={11} /> Export
        </button>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
          <FileSearch size={13} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            Decision audit trail
          </span>
          <span className="ml-auto text-muted text-[10px]">
            {entries?.total ?? 0} decision{entries?.total === 1 ? '' : 's'}
          </span>
        </div>

        {!entries ? (
          <p className="p-3 text-muted text-xs">Loading…</p>
        ) : entries.entries.length === 0 ? (
          <p className="p-3 text-muted text-xs">
            No decisions recorded yet. They appear here as the agent works.
          </p>
        ) : (
          entries.entries.map(e => <Entry key={e.incident_id} entry={e} />)
        )}
      </div>

      {entries?.note && (
        <p className="text-muted text-[10px] leading-relaxed px-1">{entries.note}</p>
      )}
    </div>
  );
}
