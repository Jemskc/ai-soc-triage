import { API_BASE as apiBase } from '../utils/api';
import { useState, useRef, useEffect, useMemo } from 'react';
import { Bot, Send, Loader, WifiOff, Sparkles } from 'lucide-react';
import { NAV_ITEMS, NAV_LABELS } from '../data/navConfig';
import { useAnalysis } from '../context/AnalysisContext';

const API_URL = apiBase;

// Openers per tab. A generic prompt list on the Evidence Graph invites a
// generic answer; these ask about what is on the screen.
const SUGGESTED_BY_TAB = {
  logs: [
    'What am I looking at on this tab?',
    'Which hosts and accounts are noisiest, and is that normal?',
    'Why did only a few of these events become alerts?',
  ],
  alerts: [
    'Explain the top incident and why it ranks first',
    'How was this queue ordered?',
    'Which of these would you work first, and why?',
  ],
  ai: [
    'Walk me through how the agent reached this verdict',
    'Which tools did it call, and what came back?',
    'What evidence would change this verdict?',
  ],
  evidence: [
    'What connects these entities?',
    'Which link matters most here?',
    'Does anything here appear in other incidents?',
  ],
  response: [
    'Why does this action need my approval?',
    'What would happen if I approved all of these?',
    'What is the autonomy band based on?',
  ],
  email: [
    'Is this email phishing, and what is the evidence?',
    'What do the SPF, DKIM and DMARC results mean here?',
    'Did anything happen on the endpoint after this email?',
  ],
  settings: [
    'Which detection rules are earning their noise?',
    'What has the AI not checked?',
  ],
};

const SUGGESTED_FALLBACK = [
  'What am I looking at on this tab?',
  'What has the AI checked, and what has it not?',
  'Which incident should I work first?',
];

// Automatically derived from navConfig — no manual updates ever needed
const ALL_TABS = NAV_ITEMS.map(t => t.label).join(', ');

/**
 * What the analyst is looking at, in words the model can use.
 *
 * The previous version branched on 'overview', 'investigations' and 'hunting'
 * — three tabs that no longer exist after the restructure — and had no branch
 * at all for AI Investigation, Evidence Graph, Response or Phishing. So on
 * exactly the screens where a question is most likely ("why did it decide
 * that?") the assistant had nothing but raw log counts.
 *
 * It also only ever saw the log array. The verdicts, the reasoning traces and
 * the risk scoring — everything the analyst is actually asking about — were
 * never sent.
 */
function buildDashboardContext({
  logs, activeNav, selectedAlert, incidents, verdicts, cases, focusedIncident,
}) {
  const lines = [];
  const L = (t) => lines.push(t);

  L(`Dashboard tabs: ${ALL_TABS}`);
  L(`Active tab: ${NAV_LABELS[activeNav] || activeNav}`);

  // ── the analysis, which is what most questions are about ────────────────
  const incs = incidents || [];
  const vs = verdicts || {};
  if (incs.length) {
    const mix = {};
    let grounded = 0, ungrounded = 0;
    Object.values(vs).forEach(v => {
      const call = String(v?.payload?.verdict || '').toUpperCase();
      if (call) mix[call] = (mix[call] || 0) + 1;
      grounded += (v?.knowledge_used || v?.grounded_in || []).length;
      ungrounded += (v?.ungrounded_techniques || v?.ungrounded_citations || []).length;
    });
    L(`AI analysis: ${Object.keys(vs).length} of ${incs.length} incidents have a verdict` +
      (Object.keys(mix).length ? ` — ${Object.entries(mix).map(([k, n]) => `${k}: ${n}`).join(', ')}` : ''));
    if (grounded || ungrounded) {
      L(`Grounding: ${grounded} citations from the knowledge base, ${ungrounded} ungrounded.`);
    }
    if (Object.keys(vs).length < incs.length) {
      L(`${incs.length - Object.keys(vs).length} incidents are still queued — the AI has not read them yet.`);
    }
  } else {
    L('No incidents have been correlated yet.');
  }

  // ── whichever incident the AI / Evidence / Response tabs are focused on ──
  const current = focusedIncident
    ? incs.find(i => i.incident_id === focusedIncident)
    : incs[0];
  const record = current ? vs[current.incident_id] : null;
  const payload = record?.payload;
  const caseFile = current ? cases?.[current.incident_id] : null;

  function describeIncident(tag) {
    if (!current) return;
    L(`${tag}: ${current.incident_id}`);
    L(`  hosts: ${(current.hosts || []).join(', ') || 'none'} | accounts: ${(current.users || []).join(', ') || 'none'}`);
    L(`  rules fired: ${(current.rules_fired || []).map(r => `${r.rule} (${r.count}x)`).join(', ') || 'none'}`);
    L(`  processes: ${(current.processes || []).map(x => String(x).split('\\').pop()).slice(0, 8).join(', ') || 'none'}`);
    L(`  events: ${current.alert_count}, first seen ${String(current.first_seen).slice(0, 19)}`);
    if (payload) {
      L(`  AI verdict: ${payload.verdict} at ${payload.confidence} confidence, urgency ${payload.urgency_score}`);
      if (payload.analyst_summary) L(`  AI summary: ${payload.analyst_summary}`);
      if (payload.mitre_technique) L(`  technique: ${payload.mitre_technique}`);
    } else {
      L('  This incident has no AI verdict yet.');
    }
    // Titles, not bare ids. Given `attack:T1021.002, attack:T1003` and two
    // rule names, the model paired them the wrong way round and told the
    // analyst Mimikatz was T1021.002. It had no way to know which was which,
    // so the mapping has to be stated rather than inferred.
    const src = record?.knowledge_used || record?.grounded_in || [];
    if (src.length) {
      L('  grounded in:');
      src.forEach(k => L(`    ${k.id}${k.title ? ` — ${k.title}` : ''}`));
    }
  }

  switch (activeNav) {
    case 'logs': {
      const rows = logs || [];
      const bySev = {};
      const ruleCounts = {}, hostCounts = {}, userCounts = {};
      rows.forEach(l => {
        if (l.severity) bySev[l.severity] = (bySev[l.severity] || 0) + 1;
        if (l.rule) ruleCounts[l.rule] = (ruleCounts[l.rule] || 0) + 1;
        if (l.host && l.host !== 'Unknown') hostCounts[l.host] = (hostCounts[l.host] || 0) + 1;
        if (l.user && l.user !== 'Unknown') userCounts[l.user] = (userCounts[l.user] || 0) + 1;
      });
      const top = (o, n = 5) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n);
      L(`Log view: ${rows.length.toLocaleString()} events loaded — ` +
        Object.entries(bySev).map(([k, n]) => `${k}: ${n}`).join(', '));
      if (top(ruleCounts).length) L(`Top rules: ${top(ruleCounts).map(([r, c]) => `"${r}" (${c}x)`).join(', ')}`);
      if (top(hostCounts, 3).length) L(`Busiest hosts: ${top(hostCounts, 3).map(([h, c]) => `${h} (${c})`).join(', ')}`);
      if (top(userCounts, 3).length) L(`Busiest accounts: ${top(userCounts, 3).map(([u, c]) => `${u} (${c})`).join(', ')}`);
      L('These are raw parsed events; only a small fraction ever reach the AI, by design.');
      break;
    }

    case 'alerts': {
      const ranked = incs
        .map(i => ({ i, p: vs[i.incident_id]?.payload }))
        .sort((a, b) => (b.p?.urgency_score ?? -1) - (a.p?.urgency_score ?? -1))
        .slice(0, 6);
      if (ranked.length) {
        L('Incident queue, highest AI urgency first:');
        ranked.forEach(({ i, p }) => L(
          `  ${i.incident_id} — ${p ? `${p.verdict} urgency ${p.urgency_score}` : 'no verdict yet'}` +
          ` | ${(i.hosts || []).join(',')} | ${(i.rules_fired || []).map(r => r.rule).slice(0, 2).join(', ')}`
        ));
      }
      if (selectedAlert) L(`Selected: ${selectedAlert.incident_id || selectedAlert.rule}`);
      break;
    }

    case 'ai': {
      describeIncident('Reasoning trace shown for');
      const inv = caseFile?.investigation;
      if (inv) {
        L(`  the agent took ${inv.step_count} steps in ${inv.elapsed_seconds}s, ${inv.model_calls} model calls`);
        if (inv.stopped_reason) L(`  stopped because: ${inv.stopped_reason}`);
        const tools = (inv.steps || []).map(st => st.tool).filter(Boolean);
        if (tools.length) L(`  tools it called, in order: ${tools.join(' -> ')}`);
        if (inv.awaiting_human) L('  this case is PARKED waiting on an analyst answer');
      } else {
        L('  no stored reasoning trace for this incident');
      }
      const risk = record?.risk || caseFile?.risk;
      if (risk) L(`  fused risk ${risk.risk_score} (${risk.band}) — deterministic, not a model call`);
      break;
    }

    case 'evidence': {
      describeIncident('Graph shown for');
      // Shared entities are the whole point of this tab.
      const shared = [];
      const seen = new Map();
      incs.forEach(i => {
        [...(i.hosts || []).map(v => ['host', v]),
         ...(i.users || []).map(v => ['account', v])].forEach(([k, v]) => {
          const key = `${k}:${v}`;
          const e = seen.get(key) || { k, v, n: 0 };
          e.n += 1; seen.set(key, e);
        });
      });
      seen.forEach(e => { if (e.n > 1) shared.push(`${e.k} ${e.v} (in ${e.n} incidents)`); });
      if (shared.length) L(`Entities spanning several incidents: ${shared.slice(0, 8).join('; ')}`);
      else L('No entity appears in more than one incident.');
      break;
    }

    case 'response': {
      describeIncident('Response plan for');
      const plan = caseFile?.agents?.response?.findings?.[0]?.data;
      if (plan?.actions?.length) {
        L('Proposed actions:');
        plan.actions.forEach(a => L(`  - ${typeof a === 'string' ? a : JSON.stringify(a)}`));
      }
      const auto = caseFile?.autonomy;
      if (auto) {
        L(`Autonomy band: ${auto.band}; approval required: ${auto.requires_approval}`);
        if (auto.reasons?.length) L(`  because: ${auto.reasons.join('; ')}`);
      }
      break;
    }

    case 'email':
      L('Phishing tab: emails are assessed through the email contract, with ATT&CK retrieval and a grounding check.');
      break;

    case 'settings':
      L('Settings: ingestion, detection-rule metrics, analyst questions and the decision audit trail.');
      break;

    default:
      break;
  }

  return lines.join('\n');
}

// ── Streaming SSE fetch ───────────────────────────────────────────────────────
async function streamAPI(body, onToken, onDone) {
  const res = await fetch(`${API_URL}/chat-stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);

  const reader = res.body.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const text = decoder.decode(value, { stream: true });
    for (const line of text.split('\n')) {
      if (!line.startsWith('data: ')) continue;
      const payload = line.slice(6).trim();
      if (payload === '[DONE]') { onDone(); return; }
      try { onToken(JSON.parse(payload)); }
      catch { onToken(payload); }
    }
  }
  onDone();
}

// ── Message bubble ────────────────────────────────────────────────────────────
/**
 * Turns incident ids in the reply into buttons that jump to that incident.
 *
 * The assistant is told to cite INC- ids precisely so the analyst can act on
 * an answer instead of copying an id and hunting for it by hand — an answer
 * you cannot navigate from is a paragraph, not a tool.
 */
// Two regexes on purpose. A /g regex carries lastIndex between calls, so
// reusing one for both split() and test() makes the test alternate true/false
// on identical input — an intermittent bug that renders some ids as links and
// others as plain text at random.
const INCIDENT_SPLIT_RE = /(INC-[0-9A-F]{6,})/g;
const INCIDENT_MATCH_RE = /^INC-[0-9A-F]{6,}$/;

function linkifyIncidents(text, onSelectIncident, known) {
  if (!text) return text;
  const parts = String(text).split(INCIDENT_SPLIT_RE);
  if (parts.length === 1) return text;
  return parts.map((part, i) => {
    if (!INCIDENT_MATCH_RE.test(part)) return part;
    // Only offer a link for an incident that exists; a hallucinated id must
    // not look navigable.
    if (!known?.has(part)) {
      return <span key={i} className="font-mono text-muted">{part}</span>;
    }
    return (
      <button
        key={i}
        onClick={() => onSelectIncident?.(part)}
        className="font-mono text-blue-400 underline decoration-dotted underline-offset-2 hover:text-blue-300"
        title="Open this incident"
      >
        {part}
      </button>
    );
  });
}

function Message({ msg, onSelectIncident, knownIncidents }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`flex gap-2 ${isUser ? 'flex-row-reverse' : ''}`}>
      {!isUser && (
        <div className="w-6 h-6 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shrink-0 mt-0.5">
          <Bot size={12} className="text-blue-400" />
        </div>
      )}
      <div className={`max-w-[85%] rounded-lg px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap ${
        isUser ? 'bg-blue-600 text-white' : 'bg-panel text-primary border border-border'
      }`}>
        {isUser
          ? msg.content
          : (linkifyIncidents(msg.content, onSelectIncident, knownIncidents)
             || (msg.streaming ? '' : '…'))}
        {msg.streaming && (
          <span className="inline-block w-1.5 h-3.5 bg-blue-400 ml-0.5 animate-pulse align-middle rounded-sm" />
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function AIPanel({
  logs = null, activeNav = 'logs', selectedAlert = null,
  focusedIncident = null, onSelectIncident = null,
}) {
  // Read the analysis directly rather than having it drilled through App: the
  // assistant is asked about verdicts and reasoning far more than about raw
  // logs, and it could not see either.
  const { incidentsByUrgency, verdicts, cases } = useAnalysis();

  const suggestions = SUGGESTED_BY_TAB[activeNav] || SUGGESTED_FALLBACK;
  // Used to decide whether an id in a reply is real enough to link.
  const knownIncidents = useMemo(
    () => new Set((incidentsByUrgency || []).map(i => i.incident_id)),
    [incidentsByUrgency],
  );
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [apiStatus, setApiStatus] = useState('unknown');
  const [modelLabel, setModelLabel] = useState('AI');
  const bottomRef = useRef(null);

  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then(r => r.json())
      .then(data => {
        setApiStatus(data.status === 'ok' ? 'ok' : 'error');
        if (data.model_short) setModelLabel(data.model_short);
      })
      .catch(() => setApiStatus('error'));
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Streaming core ────────────────────────────────────────────────────────
  async function startStream(text, body) {
    setMessages(m => [
      ...m,
      { role: 'user', content: text },
      { role: 'assistant', content: '', streaming: true },
    ]);
    setLoading(true);

    try {
      await streamAPI(
        body,
        (token) => {
          setMessages(m => {
            const copy = [...m];
            const last = copy[copy.length - 1];
            copy[copy.length - 1] = { ...last, content: last.content + token };
            return copy;
          });
        },
        () => {
          setMessages(m => {
            const copy = [...m];
            copy[copy.length - 1] = { ...copy[copy.length - 1], streaming: false };
            return copy;
          });
          setLoading(false);
        },
      );
    } catch (err) {
      setMessages(m => {
        const copy = [...m];
        copy[copy.length - 1] = {
          role: 'assistant',
          content: `API unreachable: ${err.message}\n\nMake sure api_server.py is running on port 8000.`,
          streaming: false,
        };
        return copy;
      });
      setLoading(false);
    }
  }

  async function sendMessage(text) {
    const trimmed = text.trim();
    if (!trimmed || loading) return;
    setInput('');

    const apiHistory = messages
      .filter(m => !m.streaming)
      .map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));

    const dashboard_context = buildDashboardContext({
      logs, activeNav, selectedAlert,
      incidents: incidentsByUrgency, verdicts, cases, focusedIncident,
    });
    // active_tab lets the backend attach that tab's contract — the question it
    // exists to answer — so the reply is about this screen, not the product.
    await startStream(trimmed, {
      message: trimmed, action: 'chat', history: apiHistory,
      dashboard_context, active_tab: activeNav,
    });
  }

  const isStreaming = messages.some(m => m.streaming);

  return (
    <aside className="w-[320px] shrink-0 border-l border-border bg-panel flex flex-col overflow-hidden">

      {/* Header */}
      <div className="px-4 py-3 border-b border-border flex items-center gap-2">
        <Bot size={14} className="text-blue-400" />
        <span className="text-primary text-sm font-medium">AI Assistant</span>
        <div className="ml-auto flex items-center gap-1.5">
          {apiStatus === 'ok' && (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-[10px] text-green-400">{modelLabel}</span>
            </>
          )}
          {apiStatus === 'error' && (
            <>
              <WifiOff size={11} className="text-red-400" />
              <span className="text-[10px] text-red-400">Offline</span>
            </>
          )}
          {apiStatus === 'unknown' && <Loader size={11} className="text-muted animate-spin" />}
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">

        {/* Welcome state */}
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full gap-4 py-8">
            <div className="w-10 h-10 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
              <Sparkles size={18} className="text-blue-400" />
            </div>
            <div className="text-center">
              <p className="text-primary text-xs font-medium mb-1">SOC AI Assistant</p>
              <p className="text-muted text-[11px]">Ask anything about security, threats, or investigations.</p>
            </div>
            <div className="w-full space-y-1.5">
              {suggestions.map(q => (
                <button
                  key={q}
                  onClick={() => sendMessage(q)}
                  disabled={loading || apiStatus === 'error'}
                  className="w-full text-left px-3 py-2 bg-hover border border-border rounded-lg text-[11px] text-muted hover:text-primary hover:border-blue-500/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <Message key={i} msg={m}
            onSelectIncident={onSelectIncident}
            knownIncidents={knownIncidents} />
        ))}
        <div ref={bottomRef} />
      </div>

      {/* API offline banner */}
      {apiStatus === 'error' && (
        <div className="px-3 pb-2">
          <p className="text-red-400 text-[10px] bg-red-500/10 border border-red-500/20 rounded px-2 py-1 text-center">
            AI offline — start api_server.py on port 8000
          </p>
        </div>
      )}

      {/* Input */}
      <div className="p-3 border-t border-border">
        <div className="flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage(input)}
            placeholder={apiStatus === 'error' ? 'AI offline…' : 'Ask anything…'}
            disabled={loading || apiStatus === 'error'}
            className="flex-1 bg-hover border border-border rounded px-3 py-2 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 transition-colors disabled:opacity-40"
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={loading || !input.trim() || apiStatus === 'error'}
            className="p-2 bg-blue-600 hover:bg-blue-500 rounded text-white transition-colors disabled:opacity-40"
          >
            {loading && !isStreaming
              ? <Loader size={12} className="animate-spin" />
              : <Send size={12} />
            }
          </button>
        </div>
      </div>

    </aside>
  );
}
