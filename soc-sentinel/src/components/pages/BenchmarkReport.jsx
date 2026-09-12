import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { FlaskConical, AlertTriangle, Info, Database } from 'lucide-react';
import { api } from '../../utils/api';

function Stat({ label, value, sub, tone = 'text-primary' }) {
  return (
    <div className="bg-panel rounded p-3">
      <p className="text-muted text-[10px] uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-xl font-mono tabular-nums ${tone}`}>{value}</p>
      {sub && <p className="text-muted text-[10px] mt-0.5 leading-relaxed">{sub}</p>}
    </div>
  );
}

function pct(v) {
  return Number.isFinite(v) ? `${(v * 100).toFixed(1)}%` : '—';
}

/**
 * The measured scorecard: how the engine performs against the labelled corpus,
 * with and without retrieval.
 *
 * The Limitations panel is not boilerplate and must not be removed. The corpus
 * is entirely malicious, so a false-positive rate is not computable from it,
 * and presenting the suppression rate as one would be wrong.
 */
export default function BenchmarkReport() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.benchmark()
      .then(d => (d.error ? setError(d.error) : setData(d)))
      .catch(e => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center gap-2 text-muted text-xs">
          <FlaskConical size={13} />
          No benchmark yet — run <code className="font-mono text-primary">scripts/benchmark.py</code>
        </div>
        <p className="text-muted text-[10px] mt-1">{error}</p>
      </div>
    );
  }

  if (!data) {
    return <div className="text-muted text-xs">Loading benchmark…</div>;
  }

  const ragOn = data.runs?.rag_on;
  const ragOff = data.runs?.rag_off;
  const ablation = data.ablation;

  const perTactic = Object.entries(ragOn?.per_tactic || {}).map(([tactic, v]) => ({
    tactic: tactic.replace(/\b\w/g, c => c.toUpperCase()),
    accuracy: Math.round((v.accuracy || 0) * 100),
    total: v.total,
  }));

  return (
    <div className="space-y-4">
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
          <FlaskConical size={14} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            Benchmark — measured against labelled ground truth
          </span>
          <span className="ml-auto text-muted text-[10px] font-mono">{data.generated_at}</span>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex items-center gap-2 text-[11px] text-muted">
            <Database size={11} />
            {data.dataset?.events?.toLocaleString()} labelled attack events →{' '}
            {data.dataset?.rule_alerts} rule alerts → {data.dataset?.incidents} incidents
            <span className="text-muted/70">({data.dataset?.source})</span>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Stat
              label="Escalation recall"
              value={pct(ragOn?.escalation_recall)}
              sub="share of known-attack incidents escalated rather than dismissed"
            />
            <Stat
              label="Tactic accuracy"
              value={pct(ragOn?.tactic_accuracy)}
              sub={`${ragOn?.tactic_correct}/${ragOn?.tactic_scored} correctly attributed`}
            />
            <Stat
              label="Ungrounded citations"
              value={ragOn?.engine_stats?.ungrounded_citations ?? '—'}
              sub="techniques cited that were not retrieved"
              tone={ragOn?.engine_stats?.ungrounded_citations ? 'text-amber-400' : 'text-emerald-400'}
            />
            <Stat
              label="Throughput"
              value={`${ragOn?.throughput?.seconds_per_incident ?? '—'}s`}
              sub="per incident, one local GPU"
            />
          </div>

          {ablation && (
            <div className="border border-border rounded p-3">
              <p className="text-muted text-[10px] uppercase tracking-wider mb-2">
                Ablation — does retrieval actually help?
              </p>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div>
                  <p className="text-muted text-[10px]">RAG off</p>
                  <p className="text-primary font-mono text-base">{pct(ragOff?.tactic_accuracy)}</p>
                </div>
                <div>
                  <p className="text-muted text-[10px]">RAG on</p>
                  <p className="text-primary font-mono text-base">{pct(ragOn?.tactic_accuracy)}</p>
                </div>
                <div>
                  <p className="text-muted text-[10px]">Delta</p>
                  <p className={`font-mono text-base ${
                    ablation.tactic_accuracy_delta > 0 ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {ablation.tactic_accuracy_delta > 0 ? '+' : ''}
                    {(ablation.tactic_accuracy_delta * 100).toFixed(1)}pp
                  </p>
                </div>
              </div>
              <p className="text-muted text-[10px] mt-2 leading-relaxed">{ablation.note}</p>
            </div>
          )}

          {perTactic.length > 0 && (
            <div>
              <p className="text-muted text-[10px] uppercase tracking-wider mb-2">
                Tactic accuracy by tactic
              </p>
              <div style={{ width: '100%', height: 220 }}>
                <ResponsiveContainer>
                  <BarChart data={perTactic} margin={{ top: 4, right: 8, bottom: 4, left: -20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ffffff12" vertical={false} />
                    <XAxis dataKey="tactic" tick={{ fontSize: 9, fill: '#94a3b8' }}
                           interval={0} angle={-25} textAnchor="end" height={60} />
                    <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} domain={[0, 100]} unit="%" />
                    <Tooltip
                      contentStyle={{ background: '#0f172a', border: '1px solid #ffffff20', fontSize: 11 }}
                      formatter={(v, _n, p) => [`${v}% (n=${p.payload.total})`, 'accuracy']}
                    />
                    <Bar dataKey="accuracy" radius={[3, 3, 0, 0]}>
                      {perTactic.map((d, i) => (
                        <Cell key={i} fill={d.accuracy >= 60 ? '#10b981' : d.accuracy >= 30 ? '#f59e0b' : '#ef4444'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Deliberately prominent. A false-positive rate cannot be computed from
          an all-malicious corpus, and claiming one would be the fastest way to
          lose a technical reader's trust. */}
      <div className="bg-card border border-amber-500/30 rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-amber-500/30 bg-amber-500/10">
          <AlertTriangle size={13} className="text-amber-400" />
          <span className="text-amber-300 text-[10px] uppercase tracking-wider font-semibold">
            Limitations of this benchmark
          </span>
        </div>
        <div className="p-4 space-y-2">
          {(data.limitations || []).map((l, i) => (
            <div key={i} className="flex items-start gap-2">
              <Info size={11} className="text-muted mt-0.5 shrink-0" />
              <p className="text-muted text-[11px] leading-relaxed">{l}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
