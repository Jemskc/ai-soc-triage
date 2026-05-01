import { useState, useRef, useEffect } from 'react';
import {
  Upload, FileText, Loader, AlertTriangle, CheckCircle, Minus,
  ExternalLink, X, Shield, Link, Paperclip, Bug, Brain,
} from 'lucide-react';
import { parseEmlFile } from '../utils/emailParser';
import { MOCK_EMAIL_STRINGS } from '../data/mockEmails';

// ── Helpers ───────────────────────────────────────────────────────────────────
function riskColor(label) {
  if (label === 'Critical') return 'text-red-400';
  if (label === 'High')     return 'text-orange-400';
  if (label === 'Medium')   return 'text-yellow-500';
  return 'text-green-400';
}
function riskBadgeBg(label) {
  if (label === 'Critical') return 'bg-red-500/20 border-red-500/40 text-red-400';
  if (label === 'High')     return 'bg-orange-500/20 border-orange-500/40 text-orange-400';
  if (label === 'Medium')   return 'bg-yellow-500/20 border-yellow-500/40 text-yellow-500';
  return 'bg-green-500/20 border-green-500/40 text-green-400';
}
function riskLevelBadge(level) {
  if (level === 'CRITICAL') return 'bg-red-500/20 border-red-500/40 text-red-400';
  if (level === 'HIGH')     return 'bg-orange-500/20 border-orange-500/40 text-orange-400';
  if (level === 'MEDIUM')   return 'bg-yellow-500/20 border-yellow-500/40 text-yellow-500';
  return 'bg-green-500/20 border-green-500/40 text-green-400';
}
function AuthIcon({ val }) {
  if (val === 'pass') return <CheckCircle size={12} className="text-green-400" />;
  if (val === 'fail') return <AlertTriangle size={12} className="text-red-400" />;
  return <Minus size={12} className="text-muted" />;
}

// ── Paste modal ───────────────────────────────────────────────────────────────
function PasteModal({ onClose, onParse }) {
  const [text, setText] = useState('');
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-panel border border-border rounded-xl w-[640px] max-h-[80vh] flex flex-col shadow-2xl">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <span className="text-primary text-sm font-medium">Paste Raw Email</span>
          <button onClick={onClose} className="text-muted hover:text-primary transition-colors"><X size={16} /></button>
        </div>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Paste full email including headers..."
          className="flex-1 bg-base font-mono text-xs text-primary p-4 resize-none focus:outline-none min-h-[300px]"
        />
        <div className="px-4 py-3 border-t border-border flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 bg-hover border border-border rounded text-xs text-muted hover:text-primary transition-colors">Cancel</button>
          <button
            onClick={() => { if (text.trim()) { onParse(text); onClose(); } }}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors"
          >
            Parse Email
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Detail panel ──────────────────────────────────────────────────────────────
const TABS = [
  { id: 'overview',     label: 'Overview',     icon: Shield },
  { id: 'headers',      label: 'Headers',      icon: FileText },
  { id: 'body',         label: 'Body',         icon: FileText },
  { id: 'urls',         label: 'URLs',         icon: Link },
  { id: 'attachments',  label: 'Attachments',  icon: Paperclip },
  { id: 'iocs',         label: 'IOCs',         icon: Bug },
  { id: 'ai',           label: 'AI Analysis',  icon: Brain },
];

const API_BASE = typeof import.meta !== 'undefined'
  ? (import.meta.env.VITE_API_URL || 'http://localhost:8000')
  : 'http://localhost:8000';

function EmailDetailPanel({ email, onStatusChange, onSendToAI, onSearchLogs }) {
  const [tab, setTab] = useState('overview');
  const [bodyMode, setBodyMode] = useState('text');
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  // Fetch real AI analysis when AI tab is opened or email changes
  useEffect(() => {
    if (tab !== 'ai') return;
    setAiAnalysis(null);
    setAiLoading(true);
    fetch(`${API_BASE}/email-analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => setAiAnalysis(data.analysis || null))
      .catch(() => setAiAnalysis(null))
      .finally(() => setAiLoading(false));
  }, [tab, email.id]);

  // ── Overview: risk score breakdown ────────────────────────────────────────
  const scoreComponents = [
    { label: 'SPF fail',          points: email.spf   === 'fail' ? 30 : 0, max: 30 },
    { label: 'DKIM fail',         points: email.dkim  === 'fail' ? 20 : 0, max: 20 },
    { label: 'DMARC fail',        points: email.dmarc === 'fail' ? 15 : 0, max: 15 },
    { label: 'Suspicious URLs',   points: Math.min(email.urls.filter(u => u.risk !== 'External').length * 10, 30), max: 30 },
    { label: 'Reply-To mismatch', points: (() => { try { const f = email.from.match(/@([\w.-]+)/)?.[1]; const r = email.replyTo?.match(/@([\w.-]+)/)?.[1]; return (f && r && f !== r) ? 20 : 0; } catch { return 0; } })(), max: 20 },
    { label: 'Attachments',       points: Math.min(email.attachments.length * 5, 20), max: 20 },
  ].filter(c => c.max > 0);

  // ── AI Assessment ─────────────────────────────────────────────────────────
  function buildAssessment() {
    let summary;
    if (email.riskScore > 85) {
      summary = 'This email exhibits multiple high-confidence phishing indicators and should be treated as malicious. The combination of authentication failures and suspicious URLs strongly suggests a credential harvesting or malware delivery attempt.';
    } else if (email.riskScore > 60) {
      summary = 'This email shows suspicious characteristics consistent with a social engineering attack. While not definitively malicious, the pattern of indicators warrants immediate investigation before any links are clicked or attachments opened.';
    } else if (email.riskScore > 30) {
      summary = 'This email contains some anomalies worth reviewing. It may be legitimate but exhibits characteristics that don\'t align with expected patterns for trusted senders.';
    } else {
      summary = 'This email appears legitimate based on authentication results and content analysis. SPF, DKIM, and DMARC checks passed, and no suspicious URLs or attachments were detected.';
    }
    const findings = [];
    if (email.spf   === 'fail') findings.push('SPF authentication failed — sender domain is not authorized');
    if (email.dkim  === 'fail') findings.push('DKIM signature invalid — email may have been tampered with in transit');
    if (email.dmarc === 'fail') findings.push('DMARC policy violation — domain owner did not authorize this sender');
    if (email.replyTo && email.replyTo !== email.from) {
      const fd = email.from.match(/@([\w.-]+)/)?.[1]; const rd = email.replyTo.match(/@([\w.-]+)/)?.[1];
      if (fd && rd && fd !== rd) findings.push(`Reply-To mismatch: replies will go to ${rd}, not ${fd}`);
    }
    const badURLs = email.urls.filter(u => u.risk !== 'External');
    if (badURLs.length) findings.push(`${badURLs.length} suspicious/shortened URL(s) detected`);
    const dangerousAttach = email.attachments.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH');
    if (dangerousAttach.length) findings.push(`Dangerous file attachment(s) detected: ${dangerousAttach.map(a => a.filename).join(', ')}`);
    if (email.mismatches?.length) findings.push(`${email.mismatches.length} link-text mismatch(es) found — displayed URL differs from actual href`);
    return { summary, findings };
  }

  const actions = {
    Safe:          ['Mark Phishing', 'Investigate'],
    Phishing:      ['Mark Safe',     'Investigate'],
    Investigating: ['Mark Safe',     'Mark Phishing'],
    Unreviewed:    ['Mark Safe',     'Mark Phishing', 'Investigate'],
  };

  const { summary, findings } = buildAssessment();

  return (
    <div className="flex-1 flex flex-col overflow-hidden border-l border-border">
      {/* Panel header */}
      <div className="p-4 border-b border-border bg-panel space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <h2 className="text-primary font-semibold text-sm leading-snug truncate">{email.subject}</h2>
            <p className="text-muted text-[10px] truncate mt-0.5">{email.from}</p>
          </div>
          <span className={`shrink-0 text-lg font-bold px-3 py-1 rounded-lg border ${riskBadgeBg(email.riskLabel)}`}>
            {email.riskScore} <span className="text-xs font-normal">{email.riskLabel}</span>
          </span>
        </div>
        <div className="flex gap-2 flex-wrap">
          {(actions[email.status] || []).map(action => (
            <button
              key={action}
              onClick={() => onStatusChange(email.id, action.replace('Mark ', ''))}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                action === 'Mark Phishing' ? 'bg-red-500/20 border border-red-500/40 text-red-400 hover:bg-red-500/30' :
                action === 'Mark Safe'     ? 'bg-green-500/20 border border-green-500/40 text-green-400 hover:bg-green-500/30' :
                'bg-hover border border-border text-primary hover:border-blue-500'
              }`}
            >{action}</button>
          ))}
          <button
            onClick={() => onSendToAI(email)}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors ml-auto"
          >
            Send to AI
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-border bg-panel px-2 overflow-x-auto">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs whitespace-nowrap transition-colors border-b-2 shrink-0 ${
                tab === t.id ? 'border-blue-500 text-primary' : 'border-transparent text-muted hover:text-primary'
              }`}
            >
              <Icon size={11} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">

        {/* ── OVERVIEW ──────────────────────────────────────────────────────── */}
        {tab === 'overview' && (
          <div className="space-y-4">
            {/* Key metadata grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                ['From',      email.from],
                ['To',        email.to],
                ['Date',      email.date],
                ['Reply-To',  email.replyTo || '—'],
                ['Origin IP', email.originIP || '—'],
                ['Status',    email.status],
              ].map(([k, v]) => {
                const highlight = k === 'Reply-To' && email.replyTo && email.from && (() => {
                  const f = email.from.match(/@([\w.-]+)/)?.[1];
                  const r = v.match(/@([\w.-]+)/)?.[1];
                  return f && r && f !== r;
                })();
                return (
                  <div key={k} className="bg-card border border-border rounded p-3">
                    <p className="text-muted text-[10px] uppercase tracking-wider mb-1">{k}</p>
                    <p className={`text-xs font-mono break-all ${highlight ? 'text-orange-400' : 'text-primary'}`}>{v}</p>
                    {highlight && <p className="text-[10px] text-orange-400 mt-1">⚠ Reply-To domain differs from From domain</p>}
                  </div>
                );
              })}
            </div>

            {/* Auth summary */}
            <div className="bg-card border border-border rounded-lg p-4">
              <p className="text-primary text-xs font-medium mb-3">Authentication</p>
              <div className="flex gap-6">
                {[['SPF', email.spf], ['DKIM', email.dkim], ['DMARC', email.dmarc]].map(([k, v]) => (
                  <div key={k} className="flex items-center gap-2">
                    <AuthIcon val={v} />
                    <span className="text-muted text-xs">{k}</span>
                    <span className={`text-xs font-semibold ${v === 'pass' ? 'text-green-400' : v === 'fail' ? 'text-red-400' : 'text-muted'}`}>
                      {v.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Risk score breakdown */}
            <div className="bg-card border border-border rounded-lg p-4">
              <p className="text-muted text-[10px] uppercase tracking-wider mb-3">Risk Score Breakdown</p>
              <div className="space-y-2">
                {scoreComponents.filter(c => c.points > 0).map(c => (
                  <div key={c.label} className="flex items-center gap-3">
                    <span className="text-muted text-xs w-36 shrink-0">{c.label}</span>
                    <div className="flex-1 bg-hover rounded-full h-1.5">
                      <div className="h-full bg-red-400 rounded-full" style={{ width: `${(c.points / 100) * 100}%` }} />
                    </div>
                    <span className="text-red-400 text-xs w-10 text-right">+{c.points}</span>
                  </div>
                ))}
                {scoreComponents.every(c => c.points === 0) && (
                  <p className="text-muted text-xs">No risk factors detected</p>
                )}
              </div>
              <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
                <span className="text-muted text-xs">Total Score</span>
                <span className={`font-bold text-sm ${riskColor(email.riskLabel)}`}>{email.riskScore}/100</span>
              </div>
            </div>

            {/* Quick stats row */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'URLs',        value: email.urls.length,        sub: `${email.urls.filter(u => u.risk !== 'External').length} suspicious` },
                { label: 'Attachments', value: email.attachments.length, sub: `${email.attachments.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length} high-risk` },
                { label: 'Domains',     value: email.domains.length,     sub: 'unique' },
              ].map(({ label, value, sub }) => (
                <div key={label} className="bg-card border border-border rounded p-3 text-center">
                  <p className="text-primary text-xl font-bold">{value}</p>
                  <p className="text-muted text-[10px]">{label}</p>
                  <p className="text-muted text-[9px]">{sub}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── HEADERS ───────────────────────────────────────────────────────── */}
        {tab === 'headers' && (
          <div className="space-y-4">
            <div className="bg-card border border-border rounded-lg p-4">
              <p className="text-primary text-xs font-medium mb-3">Authentication Results</p>
              <div className="space-y-2">
                {[['SPF', email.spf], ['DKIM', email.dkim], ['DMARC', email.dmarc]].map(([k, v]) => (
                  <div key={k} className="flex items-center gap-3">
                    <span className="text-muted text-xs w-12">{k}</span>
                    <AuthIcon val={v} />
                    <span className={`text-xs font-semibold ${v === 'pass' ? 'text-green-400' : v === 'fail' ? 'text-red-400' : 'text-muted'}`}>
                      {v.toUpperCase()}
                    </span>
                    <span className="text-muted text-xs">
                      {v === 'pass' ? 'Authentication passed' : v === 'fail' ? 'Authentication failed' : 'No record found'}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {email.originIP && (
              <div className="bg-card border border-border rounded-lg p-4">
                <p className="text-primary text-xs font-medium mb-2">Origin IP</p>
                <div className="flex items-center gap-3">
                  <code className="text-blue-400 font-mono text-xs">{email.originIP}</code>
                  {onSearchLogs && (
                    <button
                      onClick={() => onSearchLogs(email.originIP)}
                      className="px-3 py-1 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors"
                    >
                      Search in Logs
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* Extended headers */}
            <div className="bg-card border border-border rounded-lg p-4 space-y-2">
              <p className="text-primary text-xs font-medium mb-3">Email Headers</p>
              {[
                ['Message-ID',     email.messageId],
                ['X-Mailer',       email.xMailer],
                ['Content-Type',   email.contentType],
                ['MIME-Version',   email.mimeVersion],
                ['X-Spam-Status',  email.xSpamStatus],
                ['X-Spam-Score',   email.xSpamScore],
                ['X-Originating-IP', email.xOriginatingIp],
                ['List-Unsubscribe', email.listUnsubscribe],
                ['DKIM-Signature', email.dkimSignature],
              ].filter(([, v]) => v).map(([k, v]) => (
                <div key={k} className="grid grid-cols-[140px_1fr] gap-2">
                  <span className="text-muted text-[10px] uppercase tracking-wide pt-0.5">{k}</span>
                  <span className="text-primary text-xs font-mono break-all">{v}</span>
                </div>
              ))}
            </div>

            {/* Received chain */}
            {email.allReceivedHeaders?.length > 0 && (
              <div className="bg-card border border-border rounded-lg p-4">
                <p className="text-primary text-xs font-medium mb-2">Received Chain ({email.allReceivedHeaders.length} hops)</p>
                <div className="space-y-1">
                  {email.allReceivedHeaders.map((h, i) => (
                    <div key={i} className="text-[10px] font-mono text-muted bg-base rounded px-2 py-1 break-all">
                      <span className="text-blue-400 mr-2">#{i + 1}</span>{h}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw auth results */}
            {email.authResults && (
              <div className="bg-card border border-border rounded-lg p-4">
                <p className="text-primary text-xs font-medium mb-2">Raw Authentication-Results</p>
                <pre className="text-[10px] font-mono text-muted bg-base rounded p-2 overflow-auto whitespace-pre-wrap">{email.authResults}</pre>
              </div>
            )}
          </div>
        )}

        {/* ── BODY ──────────────────────────────────────────────────────────── */}
        {tab === 'body' && (
          <div className="space-y-3">
            <div className="flex gap-2">
              <button
                onClick={() => setBodyMode('text')}
                className={`px-3 py-1.5 rounded text-xs transition-colors ${bodyMode === 'text' ? 'bg-blue-600 text-white' : 'bg-hover border border-border text-muted hover:text-primary'}`}
              >Plain Text</button>
              <button
                onClick={() => setBodyMode('html')}
                className={`px-3 py-1.5 rounded text-xs transition-colors ${bodyMode === 'html' ? 'bg-blue-600 text-white' : 'bg-hover border border-border text-muted hover:text-primary'}`}
              >HTML Preview</button>
            </div>

            {email.urls.some(u => u.risk !== 'External') && (
              <div className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
                <AlertTriangle size={12} /> Suspicious URLs detected in email body
              </div>
            )}

            {email.mismatches?.length > 0 && (
              <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3 space-y-2">
                <div className="flex items-center gap-2 text-orange-400 text-xs font-medium">
                  <AlertTriangle size={12} /> {email.mismatches.length} Link-Text Mismatch{email.mismatches.length > 1 ? 'es' : ''}
                </div>
                {email.mismatches.map((m, i) => (
                  <div key={i} className="text-[10px] space-y-0.5">
                    <div><span className="text-muted">Displayed: </span><span className="text-orange-300 font-mono">{m.displayText}</span></div>
                    <div><span className="text-muted">Actual href: </span><span className="text-red-400 font-mono">{m.href}</span></div>
                  </div>
                ))}
              </div>
            )}

            {bodyMode === 'text' ? (
              <pre className="bg-base border border-border rounded p-3 text-xs text-primary font-mono whitespace-pre-wrap overflow-auto max-h-96">
                {email.bodyText || '(No plain text body)'}
              </pre>
            ) : (
              email.bodyHtml ? (
                <iframe
                  srcDoc={email.bodyHtml}
                  sandbox="allow-same-origin"
                  className="w-full h-80 border border-border rounded bg-white"
                  title="Email HTML Preview"
                />
              ) : <p className="text-muted text-xs">No HTML body available</p>
            )}
          </div>
        )}

        {/* ── URLS ──────────────────────────────────────────────────────────── */}
        {tab === 'urls' && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              {['External', 'Shortened', 'Suspicious'].map(risk => {
                const count = email.urls.filter(u => u.risk === risk).length;
                const colors = { External: 'text-muted border-border', Shortened: 'text-yellow-500 border-yellow-500/40', Suspicious: 'text-red-400 border-red-500/40' };
                return (
                  <div key={risk} className={`px-3 py-1.5 rounded border text-xs ${colors[risk]}`}>
                    {count} {risk}
                  </div>
                );
              })}
            </div>

            {email.urls.length ? (
              <div className="space-y-2">
                {email.urls.map((u, i) => (
                  <div
                    key={i}
                    className={`rounded border p-3 text-xs ${
                      u.risk === 'Suspicious' ? 'bg-red-500/10 border-red-500/30' :
                      u.risk === 'Shortened'  ? 'bg-yellow-500/10 border-yellow-500/30' :
                      'bg-card border-border'
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      {u.risk !== 'External' && <AlertTriangle size={11} className={u.risk === 'Suspicious' ? 'text-red-400 shrink-0 mt-0.5' : 'text-yellow-500 shrink-0 mt-0.5'} />}
                      <div className="flex-1 min-w-0">
                        <p className="font-mono text-primary break-all text-[11px]">{u.url}</p>
                        <div className="flex items-center gap-3 mt-1">
                          <span className="text-muted text-[10px]">{u.domain}</span>
                          <span className={`text-[10px] font-semibold ${u.risk === 'Suspicious' ? 'text-red-400' : u.risk === 'Shortened' ? 'text-yellow-500' : 'text-muted'}`}>
                            {u.risk}
                          </span>
                        </div>
                      </div>
                      <a href={u.url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 shrink-0">
                        <ExternalLink size={12} />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted text-xs">No URLs found</p>
            )}

            {email.domains.length > 0 && (
              <div>
                <p className="text-primary text-xs font-medium mb-2">Unique Domains ({email.domains.length})</p>
                <div className="flex flex-wrap gap-1.5">
                  {email.domains.map(d => (
                    <span key={d} className="px-2 py-1 bg-hover border border-border rounded text-[10px] font-mono text-primary">{d}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── ATTACHMENTS ───────────────────────────────────────────────────── */}
        {tab === 'attachments' && (
          <div className="space-y-3">
            {email.attachments.length ? (
              <div className="space-y-2">
                {email.attachments.map((a, i) => (
                  <div
                    key={i}
                    className={`rounded-lg border p-3 ${
                      a.riskLevel === 'CRITICAL' ? 'bg-red-500/10 border-red-500/40' :
                      a.riskLevel === 'HIGH'     ? 'bg-orange-500/10 border-orange-500/40' :
                      a.riskLevel === 'MEDIUM'   ? 'bg-yellow-500/10 border-yellow-500/40' :
                      'bg-card border-border'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      {(a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH') && (
                        <AlertTriangle size={14} className={a.riskLevel === 'CRITICAL' ? 'text-red-400 shrink-0' : 'text-orange-400 shrink-0'} />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-primary text-xs font-mono truncate">{a.filename}</p>
                        <div className="flex items-center gap-3 mt-1">
                          <span className="text-muted text-[10px]">{a.mimeType}</span>
                          <span className="text-muted text-[10px]">{a.encoding}</span>
                          <span className="text-muted text-[10px]">~{(a.size / 1024).toFixed(1)} KB</span>
                        </div>
                      </div>
                      <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold shrink-0 ${riskLevelBadge(a.riskLevel)}`}>
                        {a.riskLevel}
                      </span>
                    </div>
                    {(a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH') && (
                      <p className="text-[10px] mt-2 pl-6" style={{ color: a.riskLevel === 'CRITICAL' ? '#f87171' : '#fb923c' }}>
                        {a.riskLevel === 'CRITICAL' ? 'Executable file — do not open without sandboxing' : 'Compressed/image file — may contain malicious payload'}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center justify-center py-10 text-muted text-xs">
                <Paperclip size={16} className="mr-2 opacity-40" /> No attachments
              </div>
            )}
          </div>
        )}

        {/* ── IOCs ──────────────────────────────────────────────────────────── */}
        {tab === 'iocs' && (
          <div className="space-y-4">
            {/* IPs */}
            {[email.originIP, email.xOriginatingIp].filter(Boolean).length > 0 && (
              <div>
                <p className="text-primary text-xs font-medium mb-2">IP Addresses</p>
                <div className="space-y-1.5">
                  {[...new Set([email.originIP, email.xOriginatingIp].filter(Boolean))].map(ip => (
                    <div key={ip} className="flex items-center gap-3 px-3 py-2 bg-card border border-border rounded text-xs">
                      <span className="text-blue-400 font-mono">{ip}</span>
                      <span className="text-muted text-[10px]">origin IP</span>
                      {onSearchLogs && (
                        <button onClick={() => onSearchLogs(ip)} className="ml-auto px-2 py-0.5 bg-hover border border-border rounded text-[10px] text-primary hover:border-blue-500 transition-colors">
                          Search Logs
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Domains */}
            {email.domains.length > 0 && (
              <div>
                <p className="text-primary text-xs font-medium mb-2">Domains</p>
                <div className="space-y-1.5">
                  {email.domains.map(d => (
                    <div key={d} className="flex items-center gap-3 px-3 py-2 bg-card border border-border rounded text-xs">
                      <span className="text-primary font-mono">{d}</span>
                      {onSearchLogs && (
                        <button onClick={() => onSearchLogs(d)} className="ml-auto px-2 py-0.5 bg-hover border border-border rounded text-[10px] text-primary hover:border-blue-500 transition-colors">
                          Search Logs
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Suspicious URLs */}
            {email.urls.filter(u => u.risk !== 'External').length > 0 && (
              <div>
                <p className="text-primary text-xs font-medium mb-2">Suspicious URLs</p>
                <div className="space-y-1.5">
                  {email.urls.filter(u => u.risk !== 'External').map((u, i) => (
                    <div key={i} className="px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-semibold ${u.risk === 'Suspicious' ? 'text-red-400' : 'text-yellow-500'}`}>{u.risk}</span>
                        <span className="text-muted text-[10px]">{u.domain}</span>
                      </div>
                      <p className="font-mono text-[10px] text-primary mt-0.5 break-all">{u.url}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Dangerous attachments */}
            {email.attachments.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length > 0 && (
              <div>
                <p className="text-primary text-xs font-medium mb-2">Malicious File Hashes (submit for analysis)</p>
                <div className="space-y-1.5">
                  {email.attachments.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').map((a, i) => (
                    <div key={i} className="px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-xs">
                      <div className="flex items-center gap-2">
                        <span className="text-red-400 font-mono">{a.filename}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold ${riskLevelBadge(a.riskLevel)}`}>{a.riskLevel}</span>
                      </div>
                      <p className="text-muted text-[10px] mt-0.5">Submit to VirusTotal or sandbox for dynamic analysis</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {email.domains.length === 0 && email.urls.filter(u => u.risk !== 'External').length === 0 &&
             !email.originIP && email.attachments.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length === 0 && (
              <div className="flex items-center justify-center py-10 text-muted text-xs">
                <Bug size={16} className="mr-2 opacity-40" /> No IOCs extracted
              </div>
            )}
          </div>
        )}

        {/* ── AI ANALYSIS ───────────────────────────────────────────────────── */}
        {tab === 'ai' && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Brain size={14} className="text-blue-400" />
              <p className="text-primary text-sm font-medium">Qwen3 Threat Assessment</p>
              <span className={`ml-auto text-xs font-semibold ${riskColor(email.riskLabel)}`}>{email.riskLabel} Risk · {email.riskScore}/100</span>
            </div>

            {/* Real AI response */}
            <div className="bg-card border border-border rounded-lg p-4 min-h-[120px]">
              {aiLoading ? (
                <div className="flex flex-col items-center justify-center h-24 gap-3">
                  <Loader size={18} className="text-blue-400 animate-spin" />
                  <p className="text-muted text-xs">Qwen3 is analyzing this email…</p>
                </div>
              ) : aiAnalysis ? (
                <p className="text-primary text-xs leading-relaxed whitespace-pre-wrap">{aiAnalysis}</p>
              ) : (
                <p className="text-muted text-xs">AI analysis unavailable — make sure api_server.py is running on port 8000.</p>
              )}
            </div>

            {/* Risk score breakdown (always shown as supporting context) */}
            <div className="bg-card border border-border rounded-lg p-4">
              <p className="text-muted text-[10px] uppercase tracking-wider mb-3">Risk Score Breakdown</p>
              <div className="space-y-2">
                {scoreComponents.filter(c => c.points > 0).map(c => (
                  <div key={c.label} className="flex items-center gap-3">
                    <span className="text-muted text-xs w-36 shrink-0">{c.label}</span>
                    <div className="flex-1 bg-hover rounded-full h-1.5">
                      <div className="h-full bg-red-400 rounded-full" style={{ width: `${(c.points / 100) * 100}%` }} />
                    </div>
                    <span className="text-red-400 text-xs w-10 text-right">+{c.points}</span>
                  </div>
                ))}
                {scoreComponents.every(c => c.points === 0) && (
                  <p className="text-muted text-xs">No risk factors detected</p>
                )}
              </div>
              <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
                <span className="text-muted text-xs">Total Score</span>
                <span className={`font-bold text-sm ${riskColor(email.riskLabel)}`}>{email.riskScore}/100</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Page component ────────────────────────────────────────────────────────────
export default function EmailAnalysis({ onSelectEmail, onSearchLogs }) {
  const [emails, setEmails] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showPaste, setShowPaste] = useState(false);
  const fileRef = useRef(null);

  const selectedEmail = emails.find(e => e.id === selectedId) || null;

  function addEmail(text) {
    const parsed = parseEmlFile(text);
    if (parsed) {
      setEmails(prev => [parsed, ...prev]);
      setSelectedId(parsed.id);
      if (onSelectEmail) onSelectEmail(parsed);
    }
  }

  function loadSamples() {
    setLoading(true);
    const parsed = MOCK_EMAIL_STRINGS.map(s => parseEmlFile(s)).filter(Boolean);
    parsed.sort((a, b) => b.riskScore - a.riskScore);
    setEmails(parsed);
    if (parsed.length) setSelectedId(parsed[0].id);
    setLoading(false);
  }

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = e => addEmail(e.target.result);
    reader.readAsText(file);
  }

  function updateStatus(id, newStatus) {
    setEmails(prev => prev.map(e => e.id === id ? { ...e, status: newStatus } : e));
  }

  const sorted = [...emails].sort((a, b) => b.riskScore - a.riskScore);

  return (
    <div className="flex flex-col h-full animate-fadeIn">
      {showPaste && <PasteModal onClose={() => setShowPaste(false)} onParse={addEmail} />}

      {/* Top action bar */}
      <div className="px-4 py-3 border-b border-border bg-panel flex items-center gap-2">
        <button
          onClick={() => fileRef.current?.click()}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors"
        >
          <Upload size={12} /> Upload .eml File
        </button>
        <button
          onClick={() => setShowPaste(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors"
        >
          <FileText size={12} /> Paste Raw Email
        </button>
        <button
          onClick={loadSamples}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors"
        >
          Load Sample Emails
        </button>
        <span className="text-muted text-xs ml-2">{emails.length} email{emails.length !== 1 ? 's' : ''} loaded</span>
        <input
          ref={fileRef} type="file" accept=".eml,.txt" className="hidden"
          onChange={e => { if (e.target.files[0]) handleFile(e.target.files[0]); e.target.value = ''; }}
        />
      </div>

      {loading && (
        <div className="flex items-center justify-center p-8">
          <Loader size={20} className="text-blue-400 animate-spin mr-3" />
          <span className="text-muted text-xs">Parsing emails...</span>
        </div>
      )}

      {!loading && emails.length === 0 && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center space-y-3">
            <Shield size={40} className="text-muted opacity-30 mx-auto" />
            <p className="text-primary font-medium text-sm">No emails loaded</p>
            <p className="text-muted text-xs">Upload a .eml file, paste raw email text, or load sample emails</p>
            <button onClick={loadSamples} className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors">
              Load Sample Emails
            </button>
          </div>
        </div>
      )}

      {!loading && emails.length > 0 && (
        <div className="flex flex-1 overflow-hidden">
          {/* Email list */}
          <div className="w-[520px] shrink-0 flex flex-col overflow-hidden border-r border-border">
            <div className="overflow-auto flex-1">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-card z-10">
                  <tr className="border-b border-border">
                    <th className="text-left text-muted px-3 py-2 font-medium w-6">#</th>
                    <th className="text-left text-muted px-3 py-2 font-medium">From / Subject</th>
                    <th className="text-left text-muted px-3 py-2 font-medium w-16">Risk</th>
                    <th className="text-left text-muted px-3 py-2 font-medium w-16">Auth</th>
                    <th className="text-left text-muted px-3 py-2 font-medium w-20">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((em, i) => (
                    <tr
                      key={em.id}
                      onClick={() => { setSelectedId(em.id); if (onSelectEmail) onSelectEmail(em); }}
                      className={`border-b border-border cursor-pointer transition-colors ${selectedId === em.id ? 'bg-hover' : 'hover:bg-hover/50'}`}
                    >
                      <td className="px-3 py-2 text-muted">{i + 1}</td>
                      <td className="px-3 py-2">
                        <p className="text-primary truncate max-w-[200px]">{em.subject}</p>
                        <p className="text-muted text-[10px] truncate max-w-[200px]">{em.from}</p>
                      </td>
                      <td className="px-3 py-2">
                        <span className={`font-bold ${riskColor(em.riskLabel)}`}>{em.riskScore}</span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex gap-1 items-center">
                          <AuthIcon val={em.spf} />
                          <AuthIcon val={em.dkim} />
                          <AuthIcon val={em.dmarc} />
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${
                          em.status === 'Phishing'      ? 'bg-red-500/20 border-red-500/40 text-red-400' :
                          em.status === 'Safe'          ? 'bg-green-500/20 border-green-500/40 text-green-400' :
                          em.status === 'Investigating' ? 'bg-orange-500/20 border-orange-500/40 text-orange-400' :
                          'bg-hover border-border text-muted'
                        }`}>{em.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selectedEmail ? (
            <EmailDetailPanel
              email={selectedEmail}
              onStatusChange={updateStatus}
              onSendToAI={em => { if (onSelectEmail) onSelectEmail(em); }}
              onSearchLogs={onSearchLogs}
            />
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-muted text-xs">Select an email to view details</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
