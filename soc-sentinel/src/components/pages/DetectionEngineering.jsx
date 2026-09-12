import { useEffect, useState } from 'react';
import {
  Wrench, AlertTriangle, CheckCircle2, MinusCircle, FlaskConical,
  ShieldOff, Play, Info,
} from 'lucide-react';
import { api } from '../../utils/api';

const LABEL_TONE = {
  'high value': 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
  noisy: 'text-red-400 border-red-500/40 bg-red-500/10',
  'possibly noisy': 'text-amber-400 border-amber-500/40 bg-amber-500/10',
  redundant: 'text-amber-400 border-amber-500/40 bg-amber-500/10',
  silent: 'text-muted border-border',
  mixed: 'text-blue-400 border-blue-500/40 bg-blue-500/10',
  'insufficient data': 'text-muted border-border',
};

function Backtest({ ruleId }) {
  const [field, setField] = useState('raw_message');
  const [pattern, setPattern] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!pattern.trim()) return;
    setBusy(true);
    try {
      setResult(await api.detectionBacktest(ruleId, field, pattern));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-2 p-2.5 rounded bg-panel border border-border space-y-2">
      <div className="flex items-center gap-1.5">
        <FlaskConical size={11} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Test an exclusion before applying it
        </span>
      </div>

      <div className="flex gap-1.5 flex-wrap">
        <select value={field} onChange={e => setField(e.target.value)}
          className="bg-base border border-border rounded px-1.5 py-1 text-[11px] text-primary">
          {['raw_message', 'process_name', 'user', 'computer', 'command_line', 'parent_process']
            .map(f => <option key={f} value={f}>{f}</option>)}
        </select>
        <input
          value={pattern}
          onChange={e => setPattern(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && run()}
          placeholder="regex, e.g. svc_backup"
          className="flex-1 min-w-[140px] bg-base border border-border rounded px-2 py-1 text-[11px] text-primary placeholder-muted focus:outline-none focus:border-blue-500"
        />
        <button onClick={run} disabled={busy || !pattern.trim()}
          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-blue-500 hover:bg-blue-600 text-white text-[11px] disabled:opacity-40">
          <Play size={10} /> {busy ? 'Testing…' : 'Backtest'}
        </button>
      </div>

      {result && !result.error && (
        <div className={`p-2 rounded border text-[11px] ${
          result.safe ? 'border-emerald-500/40 bg-emerald-500/5'
                      : 'border-red-500/40 bg-red-500/5'
        }`}>
          <div className="flex items-center gap-1.5 mb-1">
            {result.safe ? <CheckCircle2 size={11} className="text-emerald-400" />
                         : <AlertTriangle size={11} className="text-red-400" />}
            <span className={result.safe ? 'text-emerald-400 font-medium' : 'text-red-400 font-medium'}>
              {result.safe ? 'Safe to apply' : 'DO NOT APPLY'}
            </span>
          </div>
          <p className="text-primary leading-relaxed">{result.assessment}</p>
          <p className="text-muted text-[10px] mt-1">
            {result.alerts_before} → {result.alerts_after} alerts
            {' · '}{Math.round(result.noise_reduction * 100)}% noise removed
            {result.escalated_incidents_lost?.length > 0 && (
              <span className="text-red-400">
                {' · '}would lose {result.escalated_incidents_lost.length} escalated incident(s)
              </span>
            )}
          </p>
        </div>
      )}
      {result?.error && <p className="text-red-400 text-[11px]">{result.error}</p>}
    </div>
  );
}

function RuleRow({ rule }) {
  const [open, setOpen] = useState(false);
  const v = rule.verdict || {};

  return (
    <div className="border-b border-border last:border-0">
      <button onClick={() => setOpen(o => !o)}
        className="w-full px-3 py-2 hover:bg-hover transition-colors text-left">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-primary text-[11px] font-mono">{rule.rule_id}</span>
          <span className="text-muted text-[11px] truncate max-w-[240px]">{rule.name}</span>
          <span className={`px-1.5 py-0.5 rounded border text-[9px] font-medium ${
            LABEL_TONE[v.label] || 'text-muted border-border'}`}>
            {v.label}
          </span>
          <span className="ml-auto text-muted text-[10px] font-mono">
            {rule.fired} fired · {rule.unique_contribution} unique
          </span>
        </div>
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2">
          <p className="text-muted text-[11px] leading-relaxed">{v.detail}</p>
          <div className="flex items-center gap-3 text-[10px] text-muted flex-wrap">
            <span>confidence: {v.confidence}</span>
            <span>action: <span className="text-primary">{v.action}</span></span>
            {rule.overlaps_with?.length > 0 && (
              <span>overlaps: {rule.overlaps_with.join(', ')}</span>
            )}
          </div>

          {/* Precision is either evidenced or explicitly absent — never guessed. */}
          <div className="text-[11px]">
            {rule.precision !== null ? (
              <span className="text-primary">
                precision {Math.round(rule.precision * 100)}%
                <span className="text-muted"> ({rule.precision_basis})</span>
              </span>
            ) : (
              <span className="text-muted inline-flex items-start gap-1">
                <Info size={10} className="mt-0.5 shrink-0" />
                {rule.precision_basis}
              </span>
            )}
          </div>

          {rule.fired > 0 && <Backtest ruleId={rule.rule_id} />}
        </div>
      )}
    </div>
  );
}

/**
 * Rule performance, and a way to test a change before making it.
 *
 * Rule tuning is permanent work in a real SOC and is usually done blind. The
 * numbers here are deterministic; the backtest is what makes a proposed change
 * safe to act on, because an exclusion that removes 90% of a rule's noise is
 * only good if it does not also remove the firings that mattered.
 */
export default function DetectionEngineering() {
  const [data, setData] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.detectionMetrics()
      .then(d => (d.error ? setError(d.error) : setData(d)))
      .catch(e => setError(e.message));
    api.detectionCoverage().then(setCoverage).catch(() => {});
  }, []);

  if (error) return <p className="text-muted text-xs">Not available: {error}</p>;
  if (!data) return <p className="text-muted text-xs">Loading rule performance…</p>;

  const s = data.summary || {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          ['Rules', s.total_rules, `${s.fired} have fired`, 'text-primary'],
          ['Silent', s.silent?.length ?? 0, 'never fired — broken or no coverage', 'text-amber-400'],
          ['Redundant', s.redundant?.length ?? 0, 'caught nothing another rule missed', 'text-amber-400'],
          ['Analyst decisions', s.analyst_decisions_available ?? 0, 'the only basis for precision', 'text-blue-400'],
        ].map(([label, value, sub, tone]) => (
          <div key={label} className="bg-panel rounded p-3">
            <p className="text-muted text-[10px] uppercase tracking-wider">{label}</p>
            <p className={`text-xl font-mono tabular-nums ${tone}`}>{value}</p>
            <p className="text-muted text-[10px] mt-0.5 leading-relaxed">{sub}</p>
          </div>
        ))}
      </div>

      {s.dominant?.length > 0 && (
        <div className="flex items-start gap-2 p-2.5 rounded border border-amber-500/30 bg-amber-500/5">
          <AlertTriangle size={12} className="text-amber-400 mt-0.5 shrink-0" />
          <p className="text-amber-300/90 text-[11px] leading-relaxed">
            {s.dominant.map(d => `${d.rule_id} produces ${Math.round(d.share * 100)}% of all alerts`).join('; ')}.
            One rule carrying the queue is usually a tuning problem rather than a threat pattern.
          </p>
        </div>
      )}

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
          <Wrench size={13} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            Rule performance
          </span>
        </div>
        {data.rules.map(r => <RuleRow key={r.rule_id} rule={r} />)}
      </div>

      {coverage?.actionable_gaps?.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
            <ShieldOff size={13} className="text-blue-400" />
            <span className="text-muted text-[10px] uppercase tracking-wider">
              Coverage gaps — {coverage.gap_count} technique(s) the telemetry could detect
            </span>
          </div>
          <div className="p-3 flex flex-wrap gap-1.5">
            {coverage.actionable_gaps.slice(0, 20).map(g => (
              <span key={g.technique_id}
                className="px-1.5 py-0.5 rounded bg-panel text-primary text-[10px] font-mono">
                {g.technique_id}
              </span>
            ))}
          </div>
          <p className="px-3 pb-3 text-muted text-[10px] leading-relaxed">{coverage.note}</p>
        </div>
      )}

      <p className="text-muted text-[10px] leading-relaxed px-1">{data.caveat}</p>
    </div>
  );
}
