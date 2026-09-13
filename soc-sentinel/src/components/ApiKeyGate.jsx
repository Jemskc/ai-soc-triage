import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import { setApiKey } from '../utils/api';

/**
 * Somewhere to put the key.
 *
 * The API was given authentication without any way to supply a credential from
 * the dashboard, so every call returned 401, the context reported an empty
 * system, and the UI fell back to "Load a log file to begin analysis" — while
 * the server sat there holding a full analysis. A lock with no keyhole is
 * worse than no lock: it fails in a way that looks like a different problem.
 */
export default function ApiKeyGate({ message }) {
  const [value, setValue] = useState('');

  function save(e) {
    e.preventDefault();
    if (!value.trim()) return;
    setApiKey(value.trim());
    window.location.reload();
  }

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <form onSubmit={save} className="w-full max-w-md space-y-4">
        <div className="flex items-center gap-2">
          <KeyRound size={16} className="text-amber-400" />
          <h2 className="text-primary text-sm font-medium">API key required</h2>
        </div>
        <p className="text-muted text-xs leading-relaxed">
          {message || 'The server rejected this browser with 401.'} The key is
          stored in this browser only and sent as a header on every request.
        </p>
        <input
          autoFocus
          type="password"
          value={value}
          onChange={e => setValue(e.target.value)}
          placeholder="paste the value of SOC_API_KEY"
          className="w-full bg-panel border border-border rounded px-3 py-2 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 font-mono"
        />
        <button
          type="submit"
          disabled={!value.trim()}
          className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded text-white text-xs font-medium transition-colors"
        >
          Save and reload
        </button>
        <p className="text-muted text-[10px] leading-relaxed">
          Running the server locally? It prints the requirement at boot, and the
          value lives in <span className="font-mono">ai-soc-triage/output/.api_key</span>.
        </p>
      </form>
    </div>
  );
}
