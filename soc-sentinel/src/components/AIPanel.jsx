import { useState, useRef, useEffect } from 'react';
import { Bot, Send, Zap, Search, Wrench, FileSearch, Loader, WifiOff, Terminal, Mail } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

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

function LoadingBubble() {
  return (
    <div className="flex gap-2">
      <div className="w-6 h-6 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shrink-0">
        <Bot size={12} className="text-blue-400" />
      </div>
      <div className="bg-panel border border-border rounded-lg px-3 py-2 flex items-center gap-2">
        <Loader size={11} className="text-blue-400 animate-spin" />
        <span className="text-muted text-xs">Thinking…</span>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function AIPanel({ logs, selectedAlert, contextType = 'none', selectedLog = null, selectedEmail = null }) {
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
    setMessages([]);
  }, [selectedAlert?.id, selectedLog?.id, selectedEmail?.id]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Streaming core ────────────────────────────────────────────────────────
  async function startStream(userLabel, body) {
    setMessages(m => [
      ...m,
      { role: 'user', content: userLabel },
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

  // ── Action senders ────────────────────────────────────────────────────────
  async function sendAction(action) {
    if (loading || !selectedAlert) return;
    const labels = { explain: 'Explain this alert', investigate: 'Investigate', ioc: 'Extract IOCs', fix: 'Suggest remediation' };
    await startStream(labels[action] || action, { action, alert: selectedAlert, history: [] });
  }

  async function sendLogAction(action) {
    if (loading || !selectedLog) return;
    const labels = { log_explain: 'Explain this event', log_relate: 'Find related events', log_iocs: 'Extract IOCs', log_mitre: 'MITRE ATT&CK mapping' };
    await startStream(labels[action] || action, { action, log: selectedLog, history: [] });
  }

  async function sendEmailAction(action) {
    if (loading || !selectedEmail) return;
    const labels = { email_explain: 'Explain this email threat', email_iocs: 'Extract IOCs', email_headers: 'Analyze headers', email_draft: 'Draft analyst note' };
    await startStream(labels[action] || action, { action, email: selectedEmail, history: [] });
  }

  async function sendMessage(text) {
    if (!text.trim() || loading) return;
    setInput('');

    const apiHistory = messages
      .filter(m => !m.streaming)
      .map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));

    const body = { message: text, action: 'chat', history: apiHistory };
    if (activeContextType === 'alert' && selectedAlert) body.alert = selectedAlert;
    if (activeContextType === 'log'   && selectedLog)   body.log   = selectedLog;
    if (activeContextType === 'email' && selectedEmail) body.email = selectedEmail;

    await startStream(text, body);
  }

  const loaded = logs && logs.length > 0;
  const activeContextType = contextType !== 'none' ? contextType : (selectedAlert ? 'alert' : selectedLog ? 'log' : selectedEmail ? 'email' : 'none');
  const isStreaming = messages.some(m => m.streaming);
  const inputPlaceholder =
    apiStatus === 'error' ? 'API offline…' :
    activeContextType === 'alert' ? 'Ask about this alert…' :
    activeContextType === 'log'   ? 'Ask about this log event…' :
    activeContextType === 'email' ? 'Ask about this email…' : 'Ask a question…';

  // ── Shared chat + input area ──────────────────────────────────────────────
  const chatArea = (
    <>
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.length === 0 && !loading && (
          <p className="text-muted text-xs text-center mt-4">
            Use a quick action or ask a question below.
          </p>
        )}
        {messages.map((m, i) => <Message key={i} msg={m} />)}
        {loading && !isStreaming && <LoadingBubble />}
        <div ref={bottomRef} />
      </div>

      <div className="p-3 border-t border-border">
        <div className="flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage(input)}
            placeholder={inputPlaceholder}
            disabled={loading || apiStatus === 'error'}
            className="flex-1 bg-hover border border-border rounded px-3 py-2 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 transition-colors disabled:opacity-40"
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={loading || !input.trim() || apiStatus === 'error'}
            className="p-2 bg-blue-600 hover:bg-blue-500 rounded text-white transition-colors disabled:opacity-40"
          >
            {loading ? <Loader size={12} className="animate-spin" /> : <Send size={12} />}
          </button>
        </div>
      </div>
    </>
  );

  return (
    <aside className="w-[320px] shrink-0 border-l border-border bg-panel flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border flex items-center gap-2">
        <Bot size={14} className="text-blue-400" />
        <span className="text-primary text-sm font-medium">AI Security Assistant</span>
        <div className="ml-auto flex items-center gap-1.5">
          {apiStatus === 'ok' && (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse2" />
              <span className="text-[10px] text-green-400">{modelLabel}</span>
            </>
          )}
          {apiStatus === 'error' && (
            <>
              <WifiOff size={11} className="text-red-400" />
              <span className="text-[10px] text-red-400">API offline</span>
            </>
          )}
          {apiStatus === 'unknown' && <Loader size={11} className="text-muted animate-spin" />}
        </div>
      </div>

      {/* No file loaded */}
      {!loaded && (
        <div className="flex-1 flex flex-col items-center justify-center px-4 text-center gap-3">
          <Bot size={32} className="text-muted opacity-30" />
          <p className="text-muted text-xs">Import a log file to enable AI analysis</p>
          <div className="flex gap-2 flex-wrap justify-center opacity-40 pointer-events-none">
            {['Explain Alert', 'Investigate', 'IOC Search', 'Suggest Fix'].map(a => (
              <button key={a} className="px-3 py-1.5 bg-hover border border-border rounded text-xs text-muted">{a}</button>
            ))}
          </div>
        </div>
      )}

      {/* File loaded, no context selected */}
      {loaded && activeContextType === 'none' && (
        <div className="flex-1 flex flex-col items-center justify-center px-4 text-center gap-3">
          <div className="bg-card border border-border rounded-lg p-4 w-full text-left space-y-2">
            <p className="text-primary text-xs font-medium">File Summary</p>
            <div className="space-y-1 text-xs">
              <div className="flex justify-between"><span className="text-muted">Total Events</span><span className="text-primary">{logs.length.toLocaleString()}</span></div>
              <div className="flex justify-between"><span className="text-muted">Critical</span><span className="text-red-400">{logs.filter(l => l.severity === 'CRITICAL').length}</span></div>
              <div className="flex justify-between"><span className="text-muted">High</span><span className="text-orange-400">{logs.filter(l => l.severity === 'HIGH').length}</span></div>
              <div className="flex justify-between"><span className="text-muted">Unique IPs</span><span className="text-primary">{new Set(logs.map(l => l.sourceIP)).size}</span></div>
            </div>
          </div>
          <p className="text-muted text-xs">Click an alert row to begin AI analysis</p>
          {apiStatus === 'error' && (
            <p className="text-red-400 text-[10px] bg-red-500/10 border border-red-500/20 rounded px-2 py-1">
              AI offline — start api_server.py on port 8000
            </p>
          )}
        </div>
      )}

      {/* Alert selected */}
      {loaded && selectedAlert && (
        <>
          <div className="p-3 border-b border-border bg-base/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="text-muted text-[10px]">SELECTED</span>
              <span className="text-primary text-[10px] font-mono font-medium">{selectedAlert.id}</span>
              <span className={`ml-auto text-[10px] font-semibold ${
                selectedAlert.severity === 'CRITICAL' ? 'text-red-400' :
                selectedAlert.severity === 'HIGH'     ? 'text-orange-400' :
                selectedAlert.severity === 'MEDIUM'   ? 'text-yellow-400' : 'text-blue-400'
              }`}>{selectedAlert.severity}</span>
            </div>
            <p className="text-primary text-xs font-medium line-clamp-1">{selectedAlert.rule}</p>
            <div className="flex gap-2 text-[10px] text-muted flex-wrap">
              <span className="font-mono">{selectedAlert.sourceIP}</span>
              <span>·</span><span>{selectedAlert.user}</span>
              <span>·</span><span>{selectedAlert.host}</span>
            </div>
          </div>

          <div className="p-3 border-b border-border">
            <div className="grid grid-cols-2 gap-1.5">
              {[
                { label: 'Explain Alert', icon: Zap,       action: 'explain' },
                { label: 'Investigate',   icon: Search,     action: 'investigate' },
                { label: 'IOC Search',    icon: FileSearch, action: 'ioc' },
                { label: 'Suggest Fix',   icon: Wrench,     action: 'fix' },
              ].map(({ label, icon: Icon, action }) => (
                <button
                  key={action}
                  onClick={() => sendAction(action)}
                  disabled={loading || apiStatus === 'error'}
                  className="flex items-center gap-1.5 px-2 py-2 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 hover:text-blue-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Icon size={11} />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {chatArea}
        </>
      )}

      {/* Log selected */}
      {activeContextType === 'log' && selectedLog && (
        <>
          <div className="p-3 border-b border-border bg-base/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <Terminal size={11} className="text-blue-400" />
              <span className="text-muted text-[10px]">LOG EVENT</span>
              <span className="text-primary text-[10px] font-mono font-medium">{selectedLog.id}</span>
              <span className={`ml-auto text-[10px] font-semibold ${
                selectedLog.severity === 'CRITICAL' ? 'text-red-400' :
                selectedLog.severity === 'HIGH'     ? 'text-orange-400' :
                selectedLog.severity === 'MEDIUM'   ? 'text-yellow-400' : 'text-blue-400'
              }`}>{selectedLog.severity}</span>
            </div>
            <p className="text-primary text-xs font-medium line-clamp-1">{selectedLog.rule}</p>
            <div className="flex gap-2 text-[10px] text-muted flex-wrap">
              <span>{new Date(selectedLog.timestamp).toLocaleTimeString()}</span>
              <span>·</span><span>{selectedLog.source}</span>
              {selectedLog.sourceIP !== 'Unknown' && <><span>·</span><span className="font-mono">{selectedLog.sourceIP}</span></>}
              {selectedLog.user !== 'Unknown' && <><span>·</span><span>{selectedLog.user}</span></>}
            </div>
          </div>

          <div className="p-3 border-b border-border">
            <div className="grid grid-cols-2 gap-1.5">
              {[
                { label: 'Explain Event', icon: Zap,       fn: () => sendLogAction('log_explain') },
                { label: 'Find Related',  icon: Search,     fn: () => sendLogAction('log_relate') },
                { label: 'IOC Extract',   icon: FileSearch, fn: () => sendLogAction('log_iocs') },
                { label: 'MITRE Map',     icon: Wrench,     fn: () => sendLogAction('log_mitre') },
              ].map(({ label, icon: Icon, fn }) => (
                <button
                  key={label}
                  onClick={fn}
                  disabled={loading}
                  className="flex items-center gap-1.5 px-2 py-2 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 hover:text-blue-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Icon size={11} />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {chatArea}
        </>
      )}

      {/* Email selected */}
      {activeContextType === 'email' && selectedEmail && (
        <>
          <div className="p-3 border-b border-border bg-base/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <Mail size={11} className="text-blue-400" />
              <span className="text-muted text-[10px]">EMAIL ANALYSIS</span>
              <span className={`ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded ${
                selectedEmail.riskLabel === 'Critical' ? 'bg-red-500/20 text-red-400' :
                selectedEmail.riskLabel === 'High'     ? 'bg-orange-500/20 text-orange-400' :
                selectedEmail.riskLabel === 'Medium'   ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-green-500/20 text-green-400'
              }`}>{selectedEmail.riskLabel} ({selectedEmail.riskScore}/100)</span>
            </div>
            <p className="text-primary text-xs font-medium line-clamp-1">{selectedEmail.subject}</p>
            <p className="text-muted text-[10px] truncate">From: {selectedEmail.from}</p>
          </div>

          <div className="p-3 border-b border-border">
            <div className="grid grid-cols-2 gap-1.5">
              {[
                { label: 'Explain Threat', icon: Zap,       fn: () => sendEmailAction('email_explain') },
                { label: 'Extract IOCs',   icon: FileSearch, fn: () => sendEmailAction('email_iocs') },
                { label: 'Check Headers',  icon: Search,     fn: () => sendEmailAction('email_headers') },
                { label: 'Draft Response', icon: Wrench,     fn: () => sendEmailAction('email_draft') },
              ].map(({ label, icon: Icon, fn }) => (
                <button
                  key={label}
                  onClick={fn}
                  disabled={loading}
                  className="flex items-center gap-1.5 px-2 py-2 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 hover:text-blue-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Icon size={11} />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {chatArea}
        </>
      )}
    </aside>
  );
}
