import { useEffect, useState } from 'react';
import { MessageCircleQuestion, Send, Clock, CheckCircle2, HelpCircle } from 'lucide-react';
import { api } from '../../utils/api';

function since(seconds) {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function QuestionCard({ q, onAnswered }) {
  const [answer, setAnswer] = useState('');
  const [sending, setSending] = useState(false);

  async function submit(text) {
    const value = (text ?? answer).trim();
    if (!value) return;
    setSending(true);
    try {
      await api.answerQuestion(q.question_id, value);
      onAnswered?.(q.question_id);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <MessageCircleQuestion size={13} className="text-amber-400" />
        <span className="text-primary text-[11px] font-mono">{q.incident_id}</span>
        <span className="ml-auto text-muted text-[10px] inline-flex items-center gap-1">
          <Clock size={9} /> waiting {since(q.waiting_seconds)}
        </span>
      </div>

      <div className="p-3 space-y-2.5">
        <p className="text-primary text-sm leading-relaxed">{q.question}</p>

        {q.why_it_matters && (
          <p className="text-muted text-[11px] leading-relaxed">
            <span className="uppercase tracking-wider text-[9px]">Why it matters: </span>
            {q.why_it_matters}
          </p>
        )}

        {q.options?.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {q.options.map(o => (
              <button
                key={o}
                onClick={() => submit(o)}
                disabled={sending}
                className="px-2 py-1 rounded border border-border text-primary text-[11px] hover:border-blue-500/50 hover:bg-hover transition-colors disabled:opacity-40"
              >
                {o}
              </button>
            ))}
          </div>
        )}

        <div className="flex gap-2">
          <input
            value={answer}
            onChange={e => setAnswer(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && submit()}
            placeholder="Or answer in your own words…"
            disabled={sending}
            className="flex-1 bg-panel border border-border rounded px-2.5 py-1.5 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 disabled:opacity-40"
          />
          <button
            onClick={() => submit()}
            disabled={sending || !answer.trim()}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-blue-500 hover:bg-blue-600 text-white text-xs disabled:opacity-40 transition-colors"
          >
            <Send size={11} /> {sending ? 'Sending…' : 'Answer'}
          </button>
        </div>

        <p className="text-muted text-[10px]">
          Answering resumes the investigation from where it paused — the agent
          keeps everything it already found.
        </p>
      </div>
    </div>
  );
}

/**
 * Questions the agent is waiting on.
 *
 * Autonomy without a way to ask is a false choice: an agent that must either
 * decide alone or give up will escalate everything ambiguous, which recreates
 * the queue this system exists to remove. Often one fact a human holds and the
 * telemetry cannot — was this change window approved? — unblocks the case.
 */
export default function AnalystQuestions({ compact = false }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  async function load() {
    try {
      setData(await api.questions());
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, []);

  const waiting = data?.questions ?? [];

  if (compact) {
    if (!waiting.length) return null;
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10">
        <MessageCircleQuestion size={11} className="text-amber-400" />
        <span className="text-amber-300 text-[10px] font-semibold">
          {waiting.length} question{waiting.length === 1 ? '' : 's'} for you
        </span>
      </span>
    );
  }

  if (error) return <p className="text-muted text-xs">Questions unavailable: {error}</p>;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <HelpCircle size={14} className="text-amber-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Agent is waiting on you
        </span>
        {data?.stats?.median_answer_seconds > 0 && (
          <span className="ml-auto text-muted text-[10px]">
            median answer time {since(data.stats.median_answer_seconds)}
          </span>
        )}
      </div>

      {waiting.length === 0 ? (
        <div className="bg-card border border-border rounded-lg p-4 flex items-center gap-2">
          <CheckCircle2 size={14} className="text-emerald-400" />
          <span className="text-muted text-xs">
            Nothing waiting. The agent asks only when a fact it needs is not in
            the telemetry.
          </span>
        </div>
      ) : (
        waiting.map(q => (
          <QuestionCard key={q.question_id} q={q} onAnswered={load} />
        ))
      )}
    </div>
  );
}
