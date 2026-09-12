import { API_BASE as apiBase } from '../utils/api';
import { useState, useRef, useEffect } from 'react';
import { Bot, Send, Loader, WifiOff, Sparkles } from 'lucide-react';
import { NAV_ITEMS, NAV_LABELS } from '../data/navConfig';

const API_URL = apiBase;

const SUGGESTED = [
  'What are signs of a brute force attack?',
  'Explain MITRE ATT&CK T1110',
  'How do I investigate a suspicious login?',
  'What does SPF, DKIM, DMARC mean?',
];

// Automatically derived from navConfig — no manual updates ever needed
const ALL_TABS = NAV_ITEMS.map(t => t.label).join(', ');

function buildDashboardContext(logs, activeNav, selectedAlert) {
  const lines = [];
  lines.push(`Dashboard tabs: ${ALL_TABS}`);
  lines.push(`Active tab: ${NAV_LABELS[activeNav] || activeNav}`);

  if (!logs || logs.length === 0) {
    lines.push('No log data loaded.');
    return lines.join('\n');
  }

  // ── Global summary ──────────────────────────────────────────────────────
  const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const ruleCounts = {}, ipCounts = {}, userCounts = {}, hostCounts = {};

  logs.forEach(l => {
    if (bySev[l.severity] !== undefined) bySev[l.severity]++;
    if (l.rule)     ruleCounts[l.rule]     = (ruleCounts[l.rule]     || 0) + 1;
    if (l.sourceIP && l.sourceIP !== 'Unknown') ipCounts[l.sourceIP] = (ipCounts[l.sourceIP] || 0) + 1;
    if (l.user     && l.user     !== 'Unknown') userCounts[l.user]   = (userCounts[l.user]   || 0) + 1;
    if (l.host     && l.host     !== 'Unknown') hostCounts[l.host]   = (hostCounts[l.host]   || 0) + 1;
  });

  const top = (obj, n = 5) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n);

  lines.push(
    `Total events: ${logs.length.toLocaleString()} — ` +
    `Critical: ${bySev.CRITICAL}, High: ${bySev.HIGH}, Medium: ${bySev.MEDIUM}, Low: ${bySev.LOW}`
  );

  const topRules = top(ruleCounts);
  if (topRules.length) lines.push(`Top triggered rules: ${topRules.map(([r, c]) => `"${r}" (${c}x)`).join(', ')}`);

  const topIPs = top(ipCounts);
  if (topIPs.length) lines.push(`Most active attacker IPs: ${topIPs.map(([ip, c]) => `${ip} (${c} events)`).join(', ')}`);

  const topUsers = top(userCounts, 3);
  if (topUsers.length) lines.push(`Most targeted users: ${topUsers.map(([u, c]) => `${u} (${c} events)`).join(', ')}`);

  const topHosts = top(hostCounts, 3);
  if (topHosts.length) lines.push(`Most targeted hosts: ${topHosts.map(([h, c]) => `${h} (${c} events)`).join(', ')}`);

  // ── Active tab deep context ─────────────────────────────────────────────
  if (activeNav === 'alerts' || activeNav === 'overview') {
    const critical = logs.filter(l => l.severity === 'CRITICAL').slice(0, 3);
    if (critical.length) {
      lines.push('Top critical alerts right now:');
      critical.forEach(a => lines.push(`  • [${a.rule}] ${a.sourceIP} → ${a.user} on ${a.host}`));
    }
  }

  if (activeNav === 'investigations' && selectedAlert) {
    const related = logs.filter(l =>
      l.sourceIP === selectedAlert.sourceIP || l.user === selectedAlert.user
    ).slice(0, 5);
    lines.push(`Investigation focus: [${selectedAlert.severity}] ${selectedAlert.rule}`);
    if (related.length > 1) lines.push(`Related events from same IP/user: ${related.length}`);
  }

  if (activeNav === 'hunting') {
    const uniqueIPs   = new Set(logs.map(l => l.sourceIP).filter(ip => ip && ip !== 'Unknown')).size;
    const uniqueUsers = new Set(logs.map(l => l.user).filter(u => u && u !== 'Unknown')).size;
    lines.push(`Threat hunting scope: ${uniqueIPs} unique source IPs, ${uniqueUsers} unique users`);
  }

  // ── Selected alert ──────────────────────────────────────────────────────
  if (selectedAlert) {
    lines.push(
      `Selected alert: [${selectedAlert.severity}] ${selectedAlert.rule} | ` +
      `IP: ${selectedAlert.sourceIP} | User: ${selectedAlert.user} | Host: ${selectedAlert.host} | ` +
      `Message: ${(selectedAlert.message || '').slice(0, 100)}`
    );
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
function Message({ msg }) {
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
        {msg.content || (msg.streaming ? '' : '…')}
        {msg.streaming && (
          <span className="inline-block w-1.5 h-3.5 bg-blue-400 ml-0.5 animate-pulse align-middle rounded-sm" />
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function AIPanel({ logs = null, activeNav = 'overview', selectedAlert = null }) {
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

    const dashboard_context = buildDashboardContext(logs, activeNav, selectedAlert);
    await startStream(trimmed, { message: trimmed, action: 'chat', history: apiHistory, dashboard_context });
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
              {SUGGESTED.map(q => (
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

        {messages.map((m, i) => <Message key={i} msg={m} />)}
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
