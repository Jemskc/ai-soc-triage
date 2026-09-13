import { useEffect, useRef, useState } from 'react';
import { API_BASE, getApiKey } from '../utils/api';

/**
 * Subscribes to the backend's server-sent event stream.
 *
 * The pipeline publishes every funnel stage, routing decision and — the point
 * of this — every step of an agent's investigation as it happens. Polling a
 * bundle that only changes when a run finishes cannot show that: an analyst
 * would wait a minute and see a verdict appear from nowhere.
 *
 * Reconnects on drop, because a dashboard left open overnight will lose the
 * connection and a silent dead stream looks identical to a quiet system.
 */
const MAX_EVENTS = 200;
const RECONNECT_MS = 3000;

export function useLiveEvents({ enabled = true } = {}) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef(null);
  const retryRef = useRef(null);

  useEffect(() => {
    if (!enabled) return undefined;
    let cancelled = false;

    function connect() {
      if (cancelled) return;
      try {
        // EventSource cannot set request headers, so the key goes in the
        // query string for this one endpoint. /stream is read-only and the
        // server accepts either form.
        const key = getApiKey();
        const url = `${API_BASE}/stream` + (key ? `?api_key=${encodeURIComponent(key)}` : '');
        const es = new EventSource(url);
        sourceRef.current = es;

        es.onopen = () => !cancelled && setConnected(true);

        es.onmessage = (msg) => {
          if (cancelled || !msg.data) return;
          try {
            const event = JSON.parse(msg.data);
            // A reset wipes the buffer. Without this the browser keeps
            // replaying the last 200 events from before the corpus was
            // cleared, so the AI Investigation tab carries on showing traces
            // for incidents that no longer exist — the dashboard contradicting
            // itself about whether anything is loaded.
            if (event.kind === 'reset') {
              setEvents([]);
              return;
            }
            setEvents(prev => [...prev, event].slice(-MAX_EVENTS));
          } catch {
            // keepalive comments and malformed frames are ignored
          }
        };

        es.onerror = () => {
          setConnected(false);
          es.close();
          if (!cancelled) {
            retryRef.current = setTimeout(connect, RECONNECT_MS);
          }
        };
      } catch {
        if (!cancelled) retryRef.current = setTimeout(connect, RECONNECT_MS);
      }
    }

    connect();
    return () => {
      cancelled = true;
      clearTimeout(retryRef.current);
      sourceRef.current?.close();
      setConnected(false);
    };
  }, [enabled]);

  return { events, connected };
}

/** Derive the live view of what the agent is doing right now. */
export function useLiveInvestigation(events) {
  let current = null;
  let steps = [];
  // Finished investigations used to be discarded the instant they completed,
  // so an analyst watching the agent work saw a trace build up and then
  // vanish, replaced by the next one. The reasoning that produced a verdict is
  // the most useful thing on the screen; it should not disappear at the moment
  // it becomes conclusive.
  const finished = [];

  for (const e of events) {
    if (e.kind === 'investigation.started') {
      current = { incidentId: e.incident_id, hosts: e.hosts || [] };
      steps = [];
    } else if (e.kind === 'investigation.step' && current) {
      steps.push({ step: e.step, tool: e.tool, thought: e.thought, args: e.args });
    } else if (e.kind === 'case.analysed') {
      if (current?.incidentId === e.incident_id) {
        finished.unshift({
          ...current,
          steps: [...steps],
          verdict: e.verdict,
          risk: e.risk?.risk_score,
          band: e.risk?.band,
          autonomy: e.autonomy,
          at: e.at,
        });
        current = null;
        steps = [];
      } else {
        // Completed without a start event in this window — still worth listing.
        finished.unshift({
          incidentId: e.incident_id, hosts: [], steps: [],
          verdict: e.verdict, risk: e.risk?.risk_score,
          band: e.risk?.band, autonomy: e.autonomy, at: e.at,
        });
      }
    }
  }
  return {
    current: current ? { ...current, steps: [...steps] } : null,
    finished: finished.slice(0, 12),
  };
}

/** Rolling funnel/queue counters from the same stream. */
export function useLiveStats(events) {
  const stats = { stages: [], analysed: 0, remaining: null, routes: null, lastVerdict: null };
  for (const e of events) {
    if (e.kind === 'funnel.stage') {
      stats.stages = [...stats.stages.filter(s => s.name !== e.name),
                      { name: e.name, in: e.events_in, out: e.events_out }];
    } else if (e.kind === 'case.analysed') {
      stats.analysed += 1;
      stats.remaining = e.remaining ?? stats.remaining;
      stats.lastVerdict = {
        incidentId: e.incident_id, verdict: e.verdict,
        band: e.autonomy, steps: e.steps,
        criticality: e.asset_criticality,
      };
    } else if (e.kind === 'routing.updated') {
      stats.routes = e.routes;
    }
  }
  return stats;
}
