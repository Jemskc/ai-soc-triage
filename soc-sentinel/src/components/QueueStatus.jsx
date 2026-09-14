import { useEffect, useState } from 'react';
import { CheckCircle2, Loader, Clock, HelpCircle } from 'lucide-react';
import { api } from '../utils/api';

/**
 * How much of the queue is done, running, waiting, or blocked.
 *
 * "AI reviewed 10 of 44" says how far along it is and nothing about what the
 * other 34 are doing — finished and unreported, in progress, queued behind
 * something, or parked waiting on a human who does not know they were asked.
 * Those four states need different responses from the analyst, and a single
 * fraction hides all of them.
 */
export default function QueueStatus({ onOpenQuestions }) {
  const [s, setS] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [status, questions] = await Promise.all([
          api.autopilotStatus().catch(() => null),
          api.questions().catch(() => null),
        ]);
        if (cancelled) return;
        const parked = (questions?.questions ?? questions ?? []).length;
        setS({ ...status, parked });
      } catch { /* transient */ }
    };
    load();
    const t = setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  if (!s) return null;

  const total = s.incidents_total ?? 0;
  const done = s.cases_analysed ?? 0;
  const parked = s.parked ?? 0;
  const running = s.stage === 'agents' ? 1 : 0;
  // Anything not decided, not parked and not currently being worked.
  const queued = Math.max(0, (s.pending_cases ?? 0) - running);

  const cells = [
    { icon: CheckCircle2, tone: 'text-emerald-400', n: done, label: 'decided',
      hint: 'Investigated and given a verdict.' },
    { icon: Loader, tone: 'text-blue-400', n: running, label: 'in progress',
      hint: 'Being investigated right now.', spin: running > 0 },
    { icon: Clock, tone: 'text-slate-400', n: queued, label: 'queued',
      hint: 'Correlated and waiting for the agent.' },
    { icon: HelpCircle, tone: 'text-amber-400', n: parked, label: 'need you',
      hint: 'The agent asked a question and cannot finish without an answer.',
      action: parked > 0 ? onOpenQuestions : null },
  ];

  // incidents_total counts what this process has funnelled. After a restart
  // it is 0 while decided cases restored from disk are not, and the header
  // read "8 of 0 decided — 0%", which looks like a broken counter rather than
  // a restored session. Report the count on its own when there is no
  // denominator to divide by.
  const known = total >= done;
  const pct = known && total ? Math.round((done / total) * 100) : 0;

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Investigation queue
        </span>
        <span className="text-primary text-[10px]">
          {known
            ? `${done.toLocaleString()} of ${total.toLocaleString()} decided`
            : `${done.toLocaleString()} decided (restored from earlier runs)`}
        </span>
        {known && <span className="ml-auto text-muted text-[10px]">{pct}%</span>}
      </div>

      <div className="h-1 bg-panel">
        <div className="h-full bg-emerald-500/70 transition-all"
             style={{ width: `${pct}%` }} />
      </div>

      <div className="grid grid-cols-4 divide-x divide-border">
        {cells.map(c => {
          const Icon = c.icon;
          const body = (
            <>
              <Icon size={12} className={`${c.tone} ${c.spin ? 'animate-spin' : ''}`} />
              <span className="text-primary text-sm font-medium">{c.n.toLocaleString()}</span>
              <span className="text-muted text-[10px]">{c.label}</span>
            </>
          );
          return c.action ? (
            <button key={c.label} onClick={c.action} title={c.hint}
              className="flex flex-col items-center gap-0.5 py-2 hover:bg-hover transition-colors">
              {body}
            </button>
          ) : (
            <div key={c.label} title={c.hint}
              className="flex flex-col items-center gap-0.5 py-2">
              {body}
            </div>
          );
        })}
      </div>

      {s.queued_batches > 0 && (
        <div className="px-3 py-1.5 border-t border-border">
          <span className="text-muted text-[10px]">
            {s.queued_batches} log batch{s.queued_batches === 1 ? '' : 'es'} still
            being processed — the incident count will keep rising.
          </span>
        </div>
      )}
    </div>
  );
}
