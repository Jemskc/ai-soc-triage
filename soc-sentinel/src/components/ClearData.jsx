import { useState } from 'react';
import { Trash2, AlertTriangle } from 'lucide-react';
import { api } from '../utils/api';

/**
 * Remove everything that has been ingested.
 *
 * Loading data was possible and unloading it was not, so the only way to start
 * clean was to delete files on the server. Worse, an analyst could not be sure
 * whether what they were looking at came from the file they just imported or
 * one loaded hours earlier — which makes every number on the screen suspect.
 *
 * Two-step by design. This throws away verdicts that took a minute of GPU each
 * and questions an analyst may have been part-way through answering, and none
 * of it is recoverable.
 */
export default function ClearData() {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function run() {
    setBusy(true); setError('');
    try {
      const r = await api.resetAll();
      setResult(r.cleared || {});
      setArmed(false);
      // The whole app is derived from what was just deleted.
      setTimeout(() => window.location.reload(), 1200);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <Trash2 size={13} className="text-red-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Clear ingested data
        </span>
      </div>

      <div className="p-3 space-y-3">
        {result ? (
          <p className="text-emerald-400 text-xs">
            Cleared {(result.events ?? 0).toLocaleString()} events,{' '}
            {result.incidents ?? 0} incidents and {result.verdicts ?? 0} verdicts.
            Reloading…
          </p>
        ) : !armed ? (
          <>
            <p className="text-muted text-[11px] leading-relaxed">
              Removes every ingested event, incident, verdict and open question,
              and empties the queue. Use it before importing a different corpus
              so the two cannot be confused.
            </p>
            <button
              onClick={() => setArmed(true)}
              className="px-3 py-1.5 bg-hover border border-border hover:border-red-500 rounded text-xs text-primary transition-colors"
            >
              Clear everything…
            </button>
          </>
        ) : (
          <>
            <div className="flex items-start gap-2">
              <AlertTriangle size={13} className="text-red-400 mt-0.5 shrink-0" />
              <p className="text-primary text-[11px] leading-relaxed">
                This cannot be undone. Verdicts took roughly a minute of GPU each,
                and any question you were part-way through answering goes with them.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={run}
                disabled={busy}
                className="px-3 py-1.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded text-xs text-white font-medium transition-colors"
              >
                {busy ? 'Clearing…' : 'Yes, clear everything'}
              </button>
              <button
                onClick={() => setArmed(false)}
                disabled={busy}
                className="px-3 py-1.5 bg-hover border border-border rounded text-xs text-muted hover:text-primary transition-colors"
              >
                Cancel
              </button>
            </div>
          </>
        )}
        {error && <p className="text-red-400 text-[11px]">Failed: {error}</p>}
      </div>
    </div>
  );
}
