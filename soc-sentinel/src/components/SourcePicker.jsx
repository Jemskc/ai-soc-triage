import { useEffect, useState } from 'react';
import { FileStack, Check } from 'lucide-react';
import { api } from '../utils/api';

/**
 * Which files have been imported, and which one you are looking at.
 *
 * The origin of an import used to be announced on the event bus and then
 * discarded, so once two files had been loaded their events were one
 * undifferentiated pile — an analyst could not answer the first question they
 * always ask, which is where a record came from.
 */
export default function SourcePicker({ selected, onSelect }) {
  const [sources, setSources] = useState([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const load = () => api.sources()
      .then(r => {
        if (cancelled) return;
        setSources(r.sources || []);
        setTotal(r.total_events || 0);
      })
      .catch(() => {});
    load();
    // Imports arrive while the analyst is looking at the page.
    const t = setInterval(load, 10000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  if (!sources.length) return null;

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <FileStack size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Imported sources
        </span>
        <span className="text-primary text-[10px]">{sources.length}</span>
        <span className="ml-auto text-muted text-[10px]">
          {total.toLocaleString()} events
        </span>
      </div>

      <div className="divide-y divide-border max-h-44 overflow-y-auto">
        <button
          onClick={() => onSelect('')}
          className={`w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-hover transition-colors ${
            !selected ? 'bg-hover' : ''}`}
        >
          {!selected ? <Check size={11} className="text-blue-400" />
                     : <span className="w-[11px]" />}
          <span className="text-primary text-[11px]">All sources</span>
          <span className="ml-auto text-muted text-[10px]">
            {total.toLocaleString()}
          </span>
        </button>

        {sources.map(s => (
          <button
            key={s.name}
            onClick={() => onSelect(s.name === selected ? '' : s.name)}
            className={`w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-hover transition-colors ${
              selected === s.name ? 'bg-hover' : ''}`}
            title={s.name}
          >
            {selected === s.name ? <Check size={11} className="text-blue-400" />
                                 : <span className="w-[11px]" />}
            <span className="text-primary text-[11px] font-mono truncate flex-1">
              {s.name}
            </span>
            <span className="text-muted text-[10px] shrink-0">
              {(s.events_in_log_view || 0).toLocaleString()}
            </span>
            {/* Ingested but no longer in the log view: the retention cap
                dropped the oldest rows. Said, not hidden. */}
            {s.events_ingested > s.events_in_log_view && (
              <span className="text-amber-400/70 text-[9px] shrink-0"
                    title={`${s.events_ingested.toLocaleString()} ingested; older rows aged out of the log view`}>
                of {s.events_ingested.toLocaleString()}
              </span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
