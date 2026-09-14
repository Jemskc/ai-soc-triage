import { useState, useEffect, useCallback } from 'react';
import { Target, CheckCircle2, AlertTriangle, XCircle, ShieldAlert,
         RefreshCw, Info } from 'lucide-react';
import { api } from '../../utils/api';

/**
 * How well the two layers actually did, against labelled ground truth.
 *
 * Everywhere else in this dashboard reports what happened. This reports
 * whether it was right — which is a different question and the only one a
 * CISO asks. It is deliberately unflattering: sample precision sits next to
 * the base-rate-corrected figure, and an intrusion the AI closed is given more
 * room than every number that merely costs time.
 *
 * Colour follows the status palette (good / warning / critical) and never
 * carries meaning alone — every state also has an icon and a word, because
 * warning and critical are not separable for a red-green colourblind reader.
 */

const POLL_MS = 15000;

// Status palette — fixed, never themed.
const GOOD = '#0ca30c';
const WARN = '#fab219';
const BAD  = '#d03b3b';
const MUTED = '#6b7280';

// Ordinal ramp for the funnel: one hue, light → dark, each step visibly
// separated. Sequential rather than categorical because the stages are an
// ordered magnitude, not distinct identities.
const FUNNEL_RAMP = ['#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf'];

const nf = n => (n == null ? '—' : Number(n).toLocaleString());
const pc = v => (v == null ? '—' : `${(v * 100).toFixed(v < 0.01 ? 4 : 1)}%`);

/** A headline number. Not a one-bar bar chart. */
function Stat({ label, value, sub, color, Icon }) {
  return (
    <div className="flex-1 min-w-[130px] bg-panel border border-border rounded-lg p-3">
      <div className="flex items-center gap-1.5 mb-1">
        {Icon && <Icon size={11} style={{ color: color || MUTED }} />}
        <span className="text-muted text-[10px] uppercase tracking-wider">{label}</span>
      </div>
      <p className="text-primary font-semibold tabular-nums" style={{ fontSize: 22, color }}>
        {value}
      </p>
      {sub && <p className="text-muted text-[10px] mt-0.5 leading-snug">{sub}</p>}
    </div>
  );
}

/** Horizontal bars, longest first, labelled directly. */
function Funnel({ stages }) {
  const max = Math.max(...stages.map(s => s.value), 1);
  const ROW = 30;
  return (
    <svg width="100%" height={stages.length * ROW + 8} role="img"
         aria-label="Events narrowing through each stage of the pipeline">
      {stages.map((s, i) => {
        const w = Math.max((s.value / max) * 72, s.value > 0 ? 0.6 : 0);
        return (
          <g key={s.label} transform={`translate(0 ${i * ROW})`}>
            <text x="0" y="14" className="fill-current text-muted" fontSize="10">
              {s.label}
            </text>
            {/* 4px rounded data-end, anchored to the baseline at x=140. */}
            <rect x="140" y="4" width={`${w}%`} height="12" rx="4"
                  fill={FUNNEL_RAMP[Math.min(i, FUNNEL_RAMP.length - 1)]}>
              <title>{`${s.label}: ${nf(s.value)}`}</title>
            </rect>
            <text x={`${w}%`} y="14" dx="146" fontSize="10"
                  className="fill-current text-primary tabular-nums">
              {nf(s.value)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/** Predicted against actual. A 2x2 table, because that is what it is. */
function Confusion({ tp, fp, fn, tn, positiveWord, negativeWord, dangerCell }) {
  const cell = (n, label, color, Icon, danger) => (
    <div className={`p-2.5 rounded border ${danger && n > 0
      ? 'border-red-500/50 bg-red-500/10' : 'border-border bg-panel'}`}>
      <div className="flex items-center gap-1">
        <Icon size={10} style={{ color }} />
        <span className="text-muted text-[9px] uppercase tracking-wider">{label}</span>
      </div>
      <p className="tabular-nums font-semibold text-[17px]" style={{ color }}>{nf(n)}</p>
    </div>
  );
  return (
    <div className="grid grid-cols-2 gap-1.5">
      {cell(tp, `${positiveWord} · real`, GOOD, CheckCircle2)}
      {cell(fp, `${positiveWord} · benign`, WARN, AlertTriangle)}
      {cell(fn, `${negativeWord} · real`, BAD, ShieldAlert, dangerCell)}
      {cell(tn, `${negativeWord} · benign`, MUTED, XCircle)}
    </div>
  );
}

function Panel({ title, note, children, right }) {
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <span className="text-muted text-[10px] uppercase tracking-wider">{title}</span>
        {right}
      </div>
      <div className="p-3 space-y-3">
        {children}
        {note && <p className="text-muted text-[10px] leading-relaxed">{note}</p>}
      </div>
    </div>
  );
}

export default function Scorecard() {
  const [data, setData] = useState(null);
  const [state, setState] = useState('loading');   // loading | ready | error
  const [error, setError] = useState('');

  const load = useCallback(() => {
    api.liveScorecard()
      .then(r => { setData(r); setState('ready'); })
      .catch(e => { setError(String(e.message || e)); setState('error'); });
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  if (state === 'loading') return <p className="text-muted text-xs">Scoring…</p>;
  if (state === 'error') {
    return <p className="text-amber-400 text-xs">Could not score — {error}</p>;
  }

  const op = data.operational || {};
  const l1 = data.layer1_detection || null;
  const l2 = data.layer2_ai || null;
  const corrected = l1?.base_rate_corrected;

  // Without labels there is no score, and saying so is the honest output.
  if (!data.ground_truth) {
    return (
      <div className="space-y-3">
        <Panel title="Not scoreable">
          <p className="text-amber-400 text-xs leading-relaxed">{data.why}</p>
          <p className="text-muted text-[11px]">{data.how_to_get_a_score}</p>
        </Panel>
        <Panel title="What happened anyway">
          <Funnel stages={[
            { label: 'Events ingested', value: op.events || 0 },
            { label: 'Grouped into incidents', value: op.incidents || 0 },
            { label: 'Investigated by the AI', value: op.verdicts || 0 },
          ]} />
        </Panel>
      </div>
    );
  }

  const attacks = l1?.attacks_in_data ?? data.attacks_in_data ?? 0;
  const total = data.labelled_events || op.events || 0;

  return (
    <div className="space-y-3">
      {/* Hero: the question the tab is named after. */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-baseline gap-3 flex-wrap">
          <Target size={16} className="text-blue-400" />
          <span className="text-primary font-semibold tabular-nums" style={{ fontSize: 34 }}>
            {nf(attacks)}
          </span>
          <span className="text-muted text-sm">
            malicious of {nf(total)} logs
            <span className="ml-2 text-primary">
              ({total ? ((attacks / total) * 100).toFixed(2) : '0'}%)
            </span>
          </span>
          <button onClick={load}
            className="ml-auto flex items-center gap-1 text-muted hover:text-primary text-[10px] transition-colors">
            <RefreshCw size={10} /> refresh
          </button>
        </div>
        <p className="text-muted text-[11px] mt-1">
          Ground truth comes from the corpus labels, not from the platform's own opinion.
        </p>
      </div>

      {/* Layer 1 — the deterministic rules. */}
      {l1 && (
        <Panel
          title="Layer 1 — detection rules"
          note={'Recall is what a detector is for: an attack the rules never surface '
              + 'cannot be investigated by anything downstream.'}
        >
          <div className="flex gap-2 flex-wrap">
            <Stat label="Attacks caught" Icon={CheckCircle2} color={GOOD}
                  value={`${nf(l1.attacks_caught)} / ${nf(attacks)}`}
                  sub={`recall ${pc(l1.recall)}`} />
            <Stat label="Attacks missed" Icon={ShieldAlert}
                  color={l1.attacks_missed > 0 ? BAD : GOOD}
                  value={nf(l1.attacks_missed)}
                  sub={l1.attacks_missed ? 'never reached the AI' : 'nothing slipped past'} />
            <Stat label="False alarms" Icon={AlertTriangle} color={WARN}
                  value={nf(l1.fp)}
                  sub={`${nf(l1.false_alarms_per_day)} per day at this volume`} />
            <Stat label="Correctly ignored" Icon={XCircle} color={MUTED}
                  value={nf(l1.tn)} sub="benign, no alert" />
          </div>

          <Confusion tp={l1.tp} fp={l1.fp} fn={l1.fn} tn={l1.tn}
                     positiveWord="Alerted" negativeWord="Silent" dangerCell />

          {/* The number that decides whether any of this is deployable. */}
          <div className="bg-panel border border-border rounded p-3 space-y-1.5">
            <p className="text-muted text-[10px] uppercase tracking-wider flex items-center gap-1">
              <Info size={10} /> Precision, honestly
            </p>
            <div className="flex gap-6 flex-wrap">
              <div>
                <p className="text-muted text-[10px]">on this sample</p>
                <p className="tabular-nums text-[17px]" style={{ color: WARN }}>
                  {pc(l1.sample_precision)}
                </p>
              </div>
              {corrected && (
                <div>
                  <p className="text-muted text-[10px]">at the real base rate</p>
                  <p className="tabular-nums text-[17px]" style={{ color: BAD }}>
                    {pc(corrected.precision)}
                  </p>
                </div>
              )}
            </div>
            {corrected && (
              <p className="text-muted text-[10px] leading-relaxed">
                Attacks are over-represented in this corpus by{' '}
                <span className="text-primary">{nf(corrected.over_represented_by)}×</span>.
                Projected over a real estate at that base rate, the same rules would
                raise <span style={{ color: BAD }}>{nf(corrected.projected_false_alarms)}</span>{' '}
                false alarms. The sample figure is the one every vendor quotes; it is
                not the one you would live with.
              </p>
            )}
          </div>
        </Panel>
      )}

      {/* Layer 2 — the agent. */}
      {l2 && (
        <Panel
          title="Layer 2 — AI investigation"
          right={l2.incidents_undecided > 0 && (
            <span className="ml-auto text-muted text-[10px]">
              {nf(l2.incidents_undecided)} still queued
            </span>
          )}
          note={l2.note}
        >
          {l2.incidents_with_a_verdict === 0 ? (
            <p className="text-muted text-xs">
              No verdicts yet — the agent takes about 85 seconds per incident and
              has {nf(l2.incidents_undecided)} to work through. This panel fills in
              as they land.
            </p>
          ) : (
            <>
              <div className="flex gap-2 flex-wrap">
                <Stat label="Intrusions closed by the AI" Icon={ShieldAlert}
                      color={l2.SUPPRESSED_BUT_REAL > 0 ? BAD : GOOD}
                      value={nf(l2.SUPPRESSED_BUT_REAL)}
                      sub="the only error that costs a breach" />
                <Stat label="Escalated, real" Icon={CheckCircle2} color={GOOD}
                      value={nf(l2.escalated_and_real)} sub={`recall ${pc(l2.recall)}`} />
                <Stat label="Escalated, benign" Icon={AlertTriangle} color={WARN}
                      value={nf(l2.escalated_but_benign)}
                      sub={`precision ${pc(l2.precision)}`} />
                <Stat label="Suppressed, benign" Icon={XCircle} color={MUTED}
                      value={nf(l2.suppressed_and_benign)} sub="noise removed correctly" />
              </div>
              <Confusion tp={l2.escalated_and_real} fp={l2.escalated_but_benign}
                         fn={l2.SUPPRESSED_BUT_REAL} tn={l2.suppressed_and_benign}
                         positiveWord="Escalated" negativeWord="Suppressed" dangerCell />
            </>
          )}
        </Panel>
      )}

      {/* What the two layers did to the volume. */}
      <Panel
        title="What the funnel removed"
        note={`${nf(op.reduction_events_to_incidents)}× reduction from events to incidents. `
            + 'A model on every log line would take hours; this is why it does not have to.'}
      >
        <Funnel stages={[
          { label: 'Events ingested', value: op.events || 0 },
          { label: 'Labelled malicious', value: attacks },
          { label: 'Raised an alert', value: (l1?.tp || 0) + (l1?.fp || 0) },
          { label: 'Grouped into incidents', value: op.incidents || 0 },
          { label: 'Investigated by the AI', value: op.verdicts || 0 },
        ]} />
      </Panel>

      {/* The same numbers as text, so identity is never colour-alone. */}
      <details className="bg-card border border-border rounded-lg">
        <summary className="px-3 py-2 bg-panel text-muted text-[10px] uppercase
                            tracking-wider cursor-pointer hover:text-primary">
          All figures as a table
        </summary>
        <table className="w-full text-[11px]">
          <tbody>
            {[
              ['Events scored', nf(total)],
              ['Labelled malicious', nf(attacks)],
              ['Layer 1 — caught (TP)', nf(l1?.tp)],
              ['Layer 1 — missed (FN)', nf(l1?.fn)],
              ['Layer 1 — false alarms (FP)', nf(l1?.fp)],
              ['Layer 1 — correctly silent (TN)', nf(l1?.tn)],
              ['Layer 1 — recall', pc(l1?.recall)],
              ['Layer 1 — precision (sample)', pc(l1?.sample_precision)],
              ['Layer 1 — precision (base-rate corrected)', pc(corrected?.precision)],
              ['Layer 2 — escalated and real', nf(l2?.escalated_and_real)],
              ['Layer 2 — escalated but benign', nf(l2?.escalated_but_benign)],
              ['Layer 2 — suppressed and benign', nf(l2?.suppressed_and_benign)],
              ['Layer 2 — suppressed but REAL', nf(l2?.SUPPRESSED_BUT_REAL)],
              ['Layer 2 — undecided', nf(l2?.incidents_undecided)],
            ].map(([k, v]) => (
              <tr key={k} className="border-t border-border">
                <td className="px-3 py-1.5 text-muted">{k}</td>
                <td className="px-3 py-1.5 text-primary font-mono tabular-nums text-right">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}
