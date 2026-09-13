// Single place the frontend talks to the analysis backend.
// Follows the API_BASE pattern already used in pages/EmailAnalysis.jsx.

// Default to the API on the same host the page came from, not localhost.
// Hardcoding localhost breaks the moment anyone opens the dashboard from
// another machine: the browser resolves it to *their* box, every call fails,
// and the app silently falls back to mock data — which looks like a working
// dashboard with no AI rather than like an outage.
const API_PORT = import.meta.env.VITE_API_PORT || '8000';

function defaultApiBase() {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  if (typeof window !== 'undefined' && window.location?.hostname) {
    return `${window.location.protocol}//${window.location.hostname}:${API_PORT}`;
  }
  return `http://localhost:${API_PORT}`;
}

const API_BASE = defaultApiBase();

// Supplied at build time (VITE_API_KEY) or pasted by the analyst and kept in
// this browser only. Sent as a header rather than a query parameter so it does
// not end up in server logs or browser history.
function apiKey() {
  if (import.meta.env.VITE_API_KEY) return import.meta.env.VITE_API_KEY;
  try {
    return localStorage.getItem('soc_api_key') || '';
  } catch {
    return '';
  }
}

export function getApiKey() {
  return apiKey();
}

export function setApiKey(key) {
  try {
    if (key) localStorage.setItem('soc_api_key', key);
    else localStorage.removeItem('soc_api_key');
  } catch {
    /* private window: the key simply is not remembered */
  }
}

function authHeaders() {
  const key = apiKey();
  return key ? { 'X-API-Key': key } : {};
}

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });
  if (res.status === 401) {
    throw new Error('401 — this API requires a key. Add it in Settings.');
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}${detail ? ` — ${detail}` : ''}`);
  }
  return res.json();
}

export const api = {
  base: API_BASE,

  health: () => request('/health'),

  // Kick off a background analysis run; returns { job_id }.
  startAnalysis: (payload = {}) =>
    request('/analyze-logs', { method: 'POST', body: JSON.stringify(payload) }),

  analysisStatus: (jobId) => request(`/analyze-status/${jobId}`),

  // The bundle every tab reads from.
  analysis: () => request('/analysis'),

  // Raw event log. Prefers the paginated API, but falls back to the static
  // dump the dev server hosts. The logs are deterministic — they need no
  // model — so viewing them must never be blocked on the backend being up or
  // on a model reload.
  events: async ({ offset = 0, limit = 1000, q, severity, host, user, eventId, source } = {}) => {
    const p = new URLSearchParams({ offset, limit });
    if (q) p.set('q', q);
    if (severity) p.set('severity', severity);
    if (host) p.set('host', host);
    if (user) p.set('user', user);
    if (eventId) p.set('event_id', eventId);
    if (source) p.set('source', source);
    try {
      return await request(`/events?${p}`);
    } catch {
      const res = await fetch('/events.json');
      if (!res.ok) throw new Error('no event log available');
      const all = await res.json();
      return {
        events: all.slice(offset, offset + limit),
        total: all.length,
        total_unfiltered: all.length,
        offset,
        limit,
        source: 'static',
      };
    }
  },

  // What has been imported, so the analyst can scope to one file.
  sources: () => request('/sources'),

  incidents: () => request('/incidents'),
  incident: (id) => request(`/incidents/${id}`),
  metrics: () => request('/metrics'),
  benchmark: () => request('/benchmark'),

  // Retrieval, exposed so the UI can show what grounded a verdict.
  kbSearch: (q, topK = 5) =>
    request(`/kb/search?q=${encodeURIComponent(q)}&top_k=${topK}`),

  // Analyst agreement feeds back into the knowledge base as correction
  // examples — this is how accuracy improves without retraining.
  sendFeedback: (body) =>
    request('/feedback', { method: 'POST', body: JSON.stringify(body) }),

  // Multi-agent SOC core
  cases: () => request('/cases'),
  case: (id) => request(`/cases/${id}`),
  agents: () => request('/agents'),

  // Decision audit trail — every AI verdict, reconstructable.
  audit: ({ q, band, limit = 100 } = {}) => {
    const p = new URLSearchParams({ limit });
    if (q) p.set('q', q);
    if (band) p.set('band', band);
    return request(`/audit?${p}`);
  },
  auditOne: (id) => request(`/audit/${id}`),

  // Questions the agent has put to an analyst. Answering resumes the parked
  // investigation from where it stopped.
  // Detection engineering. The metrics are deterministic; the backtest is what
  // makes a proposed rule change safe to act on.
  detectionMetrics: () => request('/detection-metrics'),
  detectionCoverage: () => request('/detection-coverage'),
  detectionBacktest: (rule_id, field, pattern) =>
    request('/detection-backtest', {
      method: 'POST',
      body: JSON.stringify({ rule_id, field, pattern }),
    }),

  questions: () => request('/questions'),
  answerQuestion: (id, answer, analyst = 'analyst') =>
    request(`/questions/${id}/answer`, {
      method: 'POST',
      body: JSON.stringify({ answer, analyst }),
    }),
  telemetryCoverage: () => request('/telemetry-coverage'),

  // Contract-driven enrichment. Every surface goes through the same path —
  // the tab's declared schema, retrieval keyed on the evidence, and the
  // grounding check — so no tab answers from a hand-written prompt.
  enrichEmail: (email) =>
    request('/enrich/email', { method: 'POST', body: JSON.stringify({ payload: email }) }),
  enrichEvent: (event) =>
    request('/enrich/event', { method: 'POST', body: JSON.stringify({ payload: event }) }),
  enrichGraph: (graph) =>
    request('/enrich/graph', { method: 'POST', body: JSON.stringify({ payload: graph }) }),

  // Send parsed events to the analysis pipeline, in batches.
  //
  // Importing used to load a file into the browser and stop there — the
  // funnel and the agents never saw it, so every tab kept showing whatever
  // the server had ingested at boot and the import looked like it had done
  // nothing. Anything the analyst imports has to reach the server or the
  // button is a lie.
  ingest: (events, origin = 'browser-import') =>
    request('/ingest', { method: 'POST', body: JSON.stringify({ events, origin }) }),

  ingestBatched: async (events, origin = 'browser-import', onProgress = null,
                        batchSize = 5000) => {
    let accepted = 0;
    for (let i = 0; i < events.length; i += batchSize) {
      const chunk = events.slice(i, i + batchSize);
      const res = await request('/ingest', {
        method: 'POST',
        body: JSON.stringify({ events: chunk, origin }),
      });
      accepted += res.accepted || 0;
      onProgress?.(Math.min(i + batchSize, events.length), events.length);
    }
    return accepted;
  },

  // Records an analyst decision on a proposed action. Nothing executes
  // server-side; this is the human gate on destructive steps.
  sendApproval: (body) =>
    request('/approve', { method: 'POST', body: JSON.stringify(body) }),
};

export { API_BASE };
