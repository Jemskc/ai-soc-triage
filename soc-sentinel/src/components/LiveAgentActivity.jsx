import { Activity, Radio, Search, Brain, WifiOff } from 'lucide-react';
import { useLiveEvents, useLiveInvestigation, useLiveStats } from '../hooks/useLiveEvents';

const TOOL_LABEL = {
  query_identity: 'checking the account',
  query_endpoint: 'checking the machine',
  query_network: 'checking network activity',
  query_asset: 'checking how important this asset is',
  check_baseline: 'comparing against normal behaviour',
  search_knowledge: 'looking up the technique',
  timeline: 'building a timeline',
  find_similar_cases: 'checking past cases',
  conclude: 'reaching a conclusion',
};

/**
 * What the AI is doing, right now.
 *
 * Deliberately written in plain language: this panel exists so a reader with no
 * security background can see the system working and understand what each step
 * means, rather than watching opaque tool names scroll past.
 */
export default function LiveAgentActivity() {
  const { events, connected } = useLiveEvents();
  const live = useLiveInvestigation(events);
  const stats = useLiveStats(events);

  if (!connected && events.length === 0) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded border border-border bg-panel">
        <WifiOff size={12} className="text-muted" />
        <span className="text-muted text-[11px]">
          Not connected to the live feed — showing saved results only.
        </span>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <Radio size={13} className={connected ? 'text-emerald-400' : 'text-muted'} />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Live agent activity
        </span>
        {connected && (
          <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            connected
          </span>
        )}
        {stats.analysed > 0 && (
          <span className="ml-auto text-muted text-[10px]">
            {stats.analysed} case{stats.analysed === 1 ? '' : 's'} completed this session
            {stats.remaining != null && ` · ${stats.remaining} waiting`}
          </span>
        )}
      </div>

      <div className="p-3 space-y-2">
        {live ? (
          <>
            <div className="flex items-center gap-2">
              <Search size={12} className="text-blue-400 animate-pulse" />
              <span className="text-primary text-xs">
                Investigating <span className="font-mono">{live.incidentId}</span>
                {live.hosts?.[0] && <span className="text-muted"> on {live.hosts[0]}</span>}
              </span>
              <span className="ml-auto text-muted text-[10px]">
                step {live.steps.length}
              </span>
            </div>

            <div className="space-y-1 pl-4 border-l border-border">
              {live.steps.slice(-6).map((s, i) => (
                <div key={i} className="text-[11px]">
                  <span className="text-primary">
                    {TOOL_LABEL[s.tool] || s.tool}
                  </span>
                  {s.thought && (
                    <p className="text-muted text-[10px] leading-relaxed italic">
                      {s.thought.slice(0, 120)}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="flex items-center gap-2">
            <Activity size={12} className="text-muted" />
            <span className="text-muted text-[11px]">
              {stats.analysed > 0
                ? 'Idle — waiting for new logs.'
                : 'Waiting for the next batch of logs.'}
            </span>
          </div>
        )}

        {stats.lastVerdict && (
          <div className="pt-2 border-t border-border flex items-center gap-2 flex-wrap text-[10px]">
            <Brain size={11} className="text-blue-400" />
            <span className="text-muted">Last decision:</span>
            <span className="text-primary font-mono">{stats.lastVerdict.incidentId}</span>
            <span className="text-primary">{stats.lastVerdict.verdict}</span>
            {stats.lastVerdict.band && (
              <span className="text-muted">→ {String(stats.lastVerdict.band).replace(/_/g, ' ')}</span>
            )}
            {stats.lastVerdict.steps && (
              <span className="text-muted">after {stats.lastVerdict.steps} steps</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
