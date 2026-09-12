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
      } catch {
        if (!cancelled) setStatus('offline');
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
        const first = await api.events({ offset: 0, limit: 5000 });
        if (cancelled) return;
        let rows = first.events || [];
        setEventTotal(first.total || rows.length);
        // Page through the remainder rather than asking for it all at once.
        while (rows.length < (first.total || 0) && !cancelled) {
          const next = await api.events({ offset: rows.length, limit: 5000 });
          if (!next.events?.length) break;
          rows = rows.concat(next.events);
        }
        if (!cancelled) setAllEvents(rows);
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
  }, [status]);

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
