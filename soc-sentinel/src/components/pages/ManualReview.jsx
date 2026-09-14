import { useState, useEffect, useCallback } from 'react';
import { UserCheck, Clock, Loader2, CheckCircle2, AlertTriangle, Trash2,
         ChevronDown, ChevronRight, BookOpen } from 'lucide-react';
import { api } from '../../utils/api';

/**
 * Logs an analyst sent to the AI themselves, and what came back.
 *
 * "Send to AI" used to drop the log into a chat panel. The answer scrolled
 * away with the conversation, was attached to no record, and could not be
 * found again — so the one place a person deliberately asked for a second
 * opinion was the one place nothing was kept.
 *
 * This queue keeps them. Status is visible while the model works, because the
 * card is shared with the investigation loop and a submission can genuinely
 * wait a couple of minutes; a spinner with no explanation reads as broken.
 */

const POLL_MS = 3000;

const STATUS = {
  queued:  { label: 'Waiting for the model', cls: 'text-amber-400 bg-amber-500/10', Icon: Clock },
  running: { label: 'Analysing',             cls: 'text-blue-300 bg-blue-500/10',   Icon: Loader2 },
  done:    { label: 'Reviewed',              cls: 'text-emerald-400 bg-emerald-500/10', Icon: CheckCircle2 },
  failed:  { label: 'Failed',                cls: 'text-red-400 bg-red-500/10',     Icon: AlertTriangle },
};

const SIGNIFICANCE = {
  noteworthy: { text: 'Worth a look',     cls: 'text-amber-400' },
  suspicious: { text: 'Suspicious',       cls: 'text-red-400' },
  routine:    { text: 'Routine — benign', cls: 'text-emerald-400' },
};

function fmt(v) {
  const t = Date.parse(v);
  return Number.isNaN(t) ? String(v ?? '')
    : new Date(t).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
}

function Verdict({ review }) {
  const payload = review.result?.payload;
  if (review.status === 'failed') {
    return (
      <p className="text-red-400 text-[11px]">
        The model could not evaluate this log — {review.error}
      </p>
    );
  }
  if (!payload) {
    return (
      <p className="text-muted text-[11px]">
        {review.status === 'running'
          ? 'The model is reading this log now.'
          : 'Waiting its turn — the same GPU is running the investigation queue.'}
      </p>
    );
  }
  const sig = SIGNIFICANCE[payload.significance]
    || { text: payload.significance || 'no call', cls: 'text-muted' };
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className={`text-[11px] font-semibold ${sig.cls}`}>{sig.text}</span>
        {payload.confidence != null && (
          <span className="text-muted text-[10px]">confidence {payload.confidence}</span>
        )}
        {review.elapsed_seconds != null && (
          <span className="ml-auto text-muted text-[10px]">
            took {review.elapsed_seconds}s
          </span>
        )}
      </div>

      <p className="text-primary text-[11px] leading-relaxed">{payload.explanation}</p>

      {payload.benign_explanation && (
        <p className="text-muted text-[10px] leading-relaxed">
          <span className="uppercase tracking-wider">Benign baseline</span>
          {' — '}{payload.benign_explanation}
        </p>
      )}

      {/* What the claim is grounded in. A technique cited with nothing behind
          it is recalled from weights, not evidenced, and the difference is the
          whole argument for trusting the answer. */}
      {!!(review.result?.knowledge_used || []).length && (
        <div className="pt-2 border-t border-border">
          <p className="text-muted text-[9px] uppercase tracking-wider mb-1 flex items-center gap-1">
            <BookOpen size={9} /> Grounded in
          </p>
          {review.result.knowledge_used.map(k => (
            <p key={k.id} className="text-blue-400 text-[10px]">{k.id} — {k.title}</p>
          ))}
        </div>
      )}
      {!!(review.result?.ungrounded_techniques || []).length && (
        <p className="text-amber-400 text-[10px]">
          cited {review.result.ungrounded_techniques.join(', ')} with no lookup behind it —
          treat that attribution as unverified
        </p>
      )}
    </div>
  );
}

function Row({ review, open, onToggle, onDelete }) {
  const st = STATUS[review.status] || STATUS.queued;
  const ev = review.event || {};
  const sig = review.result?.payload?.significance;
  const sigCls = SIGNIFICANCE[sig]?.cls || 'text-muted';

  return (
    <div className="border-b border-border last:border-0">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-hover transition-colors"
      >
        {open ? <ChevronDown size={12} className="text-muted shrink-0" />
              : <ChevronRight size={12} className="text-muted shrink-0" />}
        <span className="font-mono text-[10px] text-blue-400 shrink-0 w-[110px]">
          {ev.uid || review.id}
        </span>
        <span className="text-muted text-[10px] font-mono shrink-0 w-[140px]">
          {fmt(ev.timestamp)}
        </span>
        <span className="text-muted text-[10px] shrink-0 w-[120px] truncate">
          {ev.host || '—'} · {ev.user || '—'}
        </span>
        <span className="text-primary text-[10px] font-mono truncate flex-1 min-w-0">
          {ev.message || ev.rule || ''}
        </span>
        {sig && (
          <span className={`text-[10px] font-semibold shrink-0 ${sigCls}`}>
            {SIGNIFICANCE[sig]?.text || sig}
          </span>
        )}
        <span className={`shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] ${st.cls}`}>
          <st.Icon size={9} className={review.status === 'running' ? 'animate-spin' : ''} />
          {st.label}
        </span>
        <span
          role="button"
          tabIndex={0}
          onClick={e => { e.stopPropagation(); onDelete(review.id); }}
          onKeyDown={e => { if (e.key === 'Enter') { e.stopPropagation(); onDelete(review.id); } }}
          title="Remove from this list"
          className="shrink-0 text-muted hover:text-red-400 transition-colors"
        >
          <Trash2 size={11} />
        </span>
      </button>

      {open && (
        <div className="px-3 pb-3 pt-1 grid grid-cols-2 gap-4 bg-base">
          <div>
            <p className="text-muted text-[10px] uppercase tracking-wider mb-1">
              AI evaluation
            </p>
            <div className="bg-panel border border-border rounded p-3">
              <Verdict review={review} />
            </div>
            {review.note && (
              <p className="text-muted text-[10px] mt-2">
                <span className="uppercase tracking-wider">Your note</span> — {review.note}
              </p>
            )}
          </div>
          <div>
            <p className="text-muted text-[10px] uppercase tracking-wider mb-1">
              The log you sent
            </p>
            <pre className="bg-panel border border-border rounded p-3 text-[10px] font-mono
                            text-primary overflow-auto max-h-64 whitespace-pre-wrap break-all">
{JSON.stringify(ev._raw ? { ...ev, _raw: undefined } : ev, null, 1)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ManualReview() {
  const [data, setData] = useState({ reviews: [], counts: {}, total: 0 });
  const [openId, setOpenId] = useState(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(() => {
    api.manualReviews()
      .then(r => { setData(r); setLoaded(true); })
      .catch(() => setLoaded(true));
  }, []);

  // Polled rather than pushed: a submission can sit behind a 90-second
  // investigation, and a list that only loads on mount would show "queued"
  // forever.
  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  function remove(id) {
    api.deleteManualReview(id).then(load).catch(() => {});
  }

  function clearAll() {
    api.clearManualReviews().then(load).catch(() => {});
  }

  const { reviews, counts } = data;

  return (
    <div className="space-y-3">
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
          <UserCheck size={13} className="text-blue-400" />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            Sent by analyst for AI review
          </span>
          <span className="text-primary text-[10px]">{data.total}</span>
          {['queued', 'running', 'done', 'failed'].map(k => counts[k] ? (
            <span key={k} className={`px-1.5 py-0.5 rounded text-[9px] ${STATUS[k].cls}`}>
              {counts[k]} {k}
            </span>
          ) : null)}
          {data.total > 0 && (
            <button onClick={clearAll}
              className="ml-auto text-muted hover:text-red-400 text-[10px] transition-colors">
              Clear all
            </button>
          )}
        </div>

        {!loaded ? (
          <p className="text-muted text-xs p-4">Loading…</p>
        ) : reviews.length === 0 ? (
          <div className="p-6 text-center space-y-1">
            <p className="text-primary text-xs">Nothing sent yet.</p>
            <p className="text-muted text-[11px]">
              Open any record in Live Logs and press <b>Send to AI review</b>.
              It is queued behind the investigation loop — they share one GPU —
              and the evaluation is kept here once it lands.
            </p>
          </div>
        ) : (
          reviews.map(r => (
            <Row key={r.id} review={r} open={openId === r.id}
                 onToggle={() => setOpenId(id => id === r.id ? null : r.id)}
                 onDelete={remove} />
          ))
        )}
      </div>
    </div>
  );
}
