import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../utils/api';

/**
 * Holds the one analysis bundle every tab renders from.
 *
 * Before this, each tab derived its own view from the raw `logs` array with a
 * local useMemo. Now the AI produces one bundle and tabs read slices of it, so
 * incident counts cannot disagree between tabs.
 *
 * `isDemoData` is deliberately prominent: if the backend is unreachable and the
 * dashboard falls back to bundled mock logs, the UI must say so rather than
 * present mock output as real analysis.
 */
const AnalysisContext = createContext(null);

// Rows fetched for aggregate views. The log explorer does not use this — it
// queries the server per page — so this only has to be big enough for the
// severity mixes and top-N tables the other tabs draw.
const EVENT_SAMPLE = 5000;

const POLL_INTERVAL_MS = 1200;

export function AnalysisProvider({ children, fallbackLogs = null }) {
  const [bundle, setBundle] = useState(null);
  const [job, setJob] = useState(null);
  const [status, setStatus] = useState('idle'); // idle | loading | running | ready | offline
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  // On mount, take whatever analysis already exists so a cold start still
  // shows real data without waiting for a run.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      setStatus('loading');
      try {
        const existing = await api.analysis();
        if (!cancelled && existing && existing.incidents) {
          setBundle(existing);
          setStatus('ready');
          return;
        }
        if (!cancelled) setStatus('idle');
      } catch (err) {
        // Tell the difference between "no analysis yet" and "you are locked
        // out". Both used to render the import screen, so an authentication
        // failure looked exactly like an empty system and the real cause was
        // invisible.
        if (cancelled) return;
        if (String(err?.message || '').startsWith('401')) {
          setStatus('unauthorised');
          setError('This API requires a key. Enter it below to continue.');
        } else {
          setStatus('offline');
        }
      }
    })();
    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [stopPolling]);

  const startAnalysis = useCallback(async (payload = {}) => {
    setError(null);
    stopPolling();
    try {
      const { job_id: jobId } = await api.startAnalysis(payload);
      setStatus('running');
      setJob({ stage: 'queued', percent: 0, message: 'Starting…' });

      pollRef.current = setInterval(async () => {
        try {
          const state = await api.analysisStatus(jobId);
          setJob(state);
          if (state.done || state.error) {
            stopPolling();
            if (state.error) {
              setError(state.error);
              setStatus('idle');
            } else {
              const fresh = await api.analysis();
              setBundle(fresh);
              setStatus('ready');
            }
          }
        } catch (err) {
          stopPolling();
          setError(err.message);
          setStatus('offline');
        }
      }, POLL_INTERVAL_MS);
    } catch (err) {
      setError(err.message);
      setStatus('offline');
    }
  }, [stopPolling]);

  // Full multi-agent case files, fetched alongside the bundle when present.
  const [cases, setCases] = useState({});

  // The complete event log. The bundle carries only a preview so the dashboard
  // paints fast; the log view needs everything, the way a SIEM does.
  const [allEvents, setAllEvents] = useState(null);
  const [eventTotal, setEventTotal] = useState(0);

  useEffect(() => {
    let cancelled = false;
    // Deliberately not gated on analysis status: raw logs are deterministic
    // and should be readable whether or not the AI has run.
    if (status === 'loading') return undefined;
    (async () => {
      try {
        // Only the first page, and only to learn the total and give the other
        // tabs a sample to compute quick statistics from.
        //
        // This used to page through the entire corpus and concatenate it, so
        // the browser held every event in memory. That is fine for the 4,633
        // event demo corpus and impossible for a real estate: a million rows
        // is roughly 274MB of JSON, and a company with a billion events a day
        // is not an edge case, it is the normal case. No SIEM downloads its
        // index to the client. The log view now asks the server for the page
        // it is showing, and the server filters before it pages.
        const first = await api.events({ offset: 0, limit: EVENT_SAMPLE });
        if (cancelled) return;
        setEventTotal(first.total || (first.events || []).length);
        setAllEvents(first.events || []);
      } catch {
        // Fall back to the bundle preview; the views still work, just shorter.
      }
    })();
    return () => { cancelled = true; };
  }, [status]);

  useEffect(() => {
    let cancelled = false;
    if (status !== 'ready') return undefined;
    (async () => {
      try {
        const listing = await api.cases();
        if (cancelled || !listing?.queue?.length) return;
        const detail = await Promise.all(
          listing.queue.map(q => api.case(q.incident_id).catch(() => null))
        );
        if (cancelled) return;
        const byId = {};
        detail.filter(Boolean).forEach(c => { byId[c.incident_id] = c; });
        setCases(byId);
      } catch {
        // Orchestrator output is optional; the dashboard works without it.
      }
    })();
    return () => { cancelled = true; };
    // Re-fetched as verdicts land. Keyed only on `status` it ran once at page
    // load, so the reasoning traces the AI produced afterwards never reached
    // the UI and the AI Investigation tab stayed empty while the agent worked.
  }, [status, Object.keys(bundle?.verdicts || {}).length]);

  const sendFeedback = useCallback(async (incidentId, agree, note = '') => {
    try {
      await api.sendFeedback({ incident_id: incidentId, agree, note });
      return true;
    } catch {
      return false;
    }
  }, []);

  const value = useMemo(() => {
    const incidents = bundle?.incidents ?? [];
    const verdicts = bundle?.verdicts ?? {};

    // Incidents ordered the way an analyst should work them: by what the AI
    // judged most urgent, not by arrival time.
    // Prefer the fused risk score when the orchestrator produced one; it
    // accounts for cross-domain corroboration, not just the triage opinion.
    const byUrgency = [...incidents].sort((a, b) => {
      const ra = verdicts[a.incident_id]?.risk?.risk_score;
      const rb = verdicts[b.incident_id]?.risk?.risk_score;
      if (Number.isFinite(ra) || Number.isFinite(rb)) {
        return (rb ?? -1) - (ra ?? -1);
      }
      const ua = verdicts[a.incident_id]?.payload?.urgency_score ?? -1;
      const ub = verdicts[b.incident_id]?.payload?.urgency_score ?? -1;
      return ub - ua;
    });

    return {
      bundle,
      // Event rows published by the backend. Without these, every log-oriented
      // view renders from an empty array while the header reports thousands of
      // events analysed.
      events: allEvents ?? bundle?.events ?? [],
      eventTotal: eventTotal || bundle?.event_total || (bundle?.events ?? []).length,
      eventsComplete: allEvents !== null,
      incidents,
      incidentsByUrgency: byUrgency,
      verdicts,
      verdictFor: (id) => verdicts[id]?.payload ?? null,
      caseFor: (id) => cases[id] ?? null,
      cases,
      telemetryCoverage: bundle?.telemetry_coverage ?? null,
      huntFindings: bundle?.hunt?.findings ?? [],
      queue: bundle?.queue ?? [],
      riskFor: (id) => verdicts[id]?.risk ?? null,
      knowledgeFor: (id) => verdicts[id]?.knowledge_used ?? [],
      campaign: bundle?.campaign ?? {},
      metrics: bundle?.metrics ?? null,
      engineStats: bundle?.engine_stats ?? null,
      job,
      status,
      error,
      startAnalysis,
      sendFeedback,
      isReady: status === 'ready' && Boolean(bundle),
      // Server-side paged query. The browser keeps one page; filtering and
      // ordering happen where the data is.
      queryEvents: api.events,
      isRunning: status === 'running',
      // True when nothing real is loaded and the UI is showing bundled mocks.
      isDemoData: status !== 'ready' && Boolean(fallbackLogs),
    };
  }, [bundle, job, status, error, startAnalysis, sendFeedback, fallbackLogs, cases, allEvents, eventTotal]);

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) throw new Error('useAnalysis must be used inside an AnalysisProvider');
  return ctx;
}

export default AnalysisContext;
