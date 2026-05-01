const FILLER_WORDS = new Set(['show','me','find','get','what','all','the','logs','log','where','give','display','list','search','for','from','events','entries','records','in','on','by','did','do','have','has','are','is','any','some','with','and','or','that','a','an','about','recent','latest','please','want','need']);

const SOURCE_KEYWORDS = [
  ['web proxy', 'Proxy'], ['cloudtrail', 'CloudTrail'], ['cloud', 'CloudTrail'],
  ['aws', 'CloudTrail'], ['event log', 'Windows'], ['windows', 'Windows'],
  ['sysmon', 'Sysmon'], ['syslog', 'Linux'], ['linux', 'Linux'],
  ['firewall', 'Firewall'], ['fw', 'Firewall'], ['proxy', 'Proxy'],
  ['endpoint', 'EDR'], ['edr', 'EDR'],
];

const SEVERITY_KEYWORDS = [
  ['critical', 'CRITICAL'], ['crit', 'CRITICAL'], ['error', 'CRITICAL'], ['errors', 'CRITICAL'],
  ['warning', 'HIGH'], ['warnings', 'HIGH'], ['high', 'HIGH'],
  ['medium', 'MEDIUM'], ['med', 'MEDIUM'],
  ['low', 'LOW'],
];

// sorted longest-match-first so 'failed login' beats 'login'
const EVENT_PATTERNS = [
  { terms: ['failed login','failed logon','login fail','auth fail','authentication fail','brute force','wrong password','invalid password','4625'], field: 'message', value: 'fail', operator: 'contains', label: 'failed login' },
  { terms: ['powershell','encoded command','invoke-expression','ps1 '], field: 'message', value: 'powershell', operator: 'contains', label: 'PowerShell execution' },
  { terms: ['remote desktop','rdp'], field: 'message', value: 'rdp', operator: 'contains', label: 'RDP' },
  { terms: ['privilege escalation','privilege','uac bypass','token imperson'], field: 'rule', value: 'privilege', operator: 'contains', label: 'privilege escalation' },
  { terms: ['lateral movement','lateral'], field: 'rule', value: 'lateral', operator: 'contains', label: 'lateral movement' },
  { terms: ['dns tunnel','dns query','dns request'], field: 'message', value: 'dns', operator: 'contains', label: 'DNS' },
  { terms: ['outbound connection','outbound','egress'], field: 'message', value: 'outbound', operator: 'contains', label: 'outbound connection' },
  { terms: ['login','logon','sign in','sign-in','authenticate','authentication','logged in'], field: 'message', value: 'login', operator: 'contains', label: 'login' },
  { terms: ['dns'], field: 'message', value: 'dns', operator: 'contains', label: 'DNS' },
];

const TIME_REFS = [
  { patterns: ['last 15 min','past 15 min','just now'],                                       label: 'Last 15m', ms: 15 * 60_000 },
  { patterns: ['last hour','past hour','last 1 hour','1 hour ago','in the last hour'],         label: 'Last 1h',  ms: 60 * 60_000 },
  { patterns: ['last 6 hour','past 6 hour','6 hours ago'],                                    label: 'Last 6h',  ms: 6 * 3600_000 },
  { patterns: ['today','this morning','this afternoon','this evening','last 24','24 hours','24h','past 24'], label: 'Last 24h', ms: 24 * 3600_000 },
  { patterns: ['yesterday'],                                                                    label: 'Last 48h', ms: 48 * 3600_000 },
  { patterns: ['this week','last week','7 days','past week','past 7','last 7'],               label: 'Last 7d',  ms: 7 * 86400_000 },
];

export function aiLogSearch(queryText, logs) {
  if (!queryText?.trim()) return { filters: [], explanation: '', translatedQuery: '', suggestedTimeRange: null };

  const lower = queryText.toLowerCase();

  // Build entity sets from loaded logs
  const knownUsers = new Set();
  const knownHosts = new Set();
  for (const l of logs) {
    if (l.user  && l.user  !== 'Unknown') knownUsers.add(l.user.toLowerCase());
    if (l.host  && l.host  !== 'Unknown') knownHosts.add(l.host.toLowerCase());
  }

  const filters = [];
  let suggestedTimeRange = null;
  const descParts = [];

  // ── 1. IPs ────────────────────────────────────────────────────────────────
  const foundIPs = [...lower.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)].map(m => m[1]);
  for (const ip of foundIPs) {
    filters.push({ field: 'sourceIP', value: ip, operator: 'equals' });
    descParts.push(`from IP ${ip}`);
  }

  // ── 2. Usernames ──────────────────────────────────────────────────────────
  const foundUsers = new Set();
  const userRxs = [
    /\buser[:\s]+([a-zA-Z0-9._@-]+)/,
    /\busername[:\s]+([a-zA-Z0-9._@-]+)/,
    /\baccount[:\s]+([a-zA-Z0-9._@-]+)/,
    /\bdid\s+([a-zA-Z0-9._@-]{3,})\b/,
    /\bfor\s+([a-zA-Z0-9._@-]{3,})(?:\s|$)/,
    /\bby\s+([a-zA-Z0-9._@-]{3,})(?:\s|$)/,
  ];
  for (const rx of userRxs) {
    const m = lower.match(rx);
    if (!m) continue;
    const cand = m[1].replace(/[?!.,;:]$/, '');
    if (knownUsers.has(cand) && !foundUsers.has(cand)) {
      foundUsers.add(cand);
      filters.push({ field: 'user', value: cand, operator: 'equals' });
      descParts.push(`for user '${cand}'`);
    }
  }
  // token sweep
  if (foundUsers.size === 0) {
    for (const tok of lower.replace(/[^a-z0-9._@-]/g, ' ').split(/\s+/)) {
      if (tok.length >= 3 && !FILLER_WORDS.has(tok) && knownUsers.has(tok)) {
        foundUsers.add(tok);
        filters.push({ field: 'user', value: tok, operator: 'equals' });
        descParts.push(`for user '${tok}'`);
        break;
      }
    }
  }

  // ── 3. Hostnames ──────────────────────────────────────────────────────────
  const foundHosts = new Set();
  const hostRxs = [
    /\bhost[:\s]+([a-zA-Z0-9._-]+)/,
    /\bmachine[:\s]+([a-zA-Z0-9._-]+)/,
    /\bcomputer[:\s]+([a-zA-Z0-9._-]+)/,
    /\bdevice[:\s]+([a-zA-Z0-9._-]+)/,
    /\bon\s+((?:WS|PC|DC|SRV|SERVER|HOST)-[a-zA-Z0-9_-]+)/i,
  ];
  for (const rx of hostRxs) {
    const m = lower.match(rx);
    if (!m) continue;
    const cand = m[1].replace(/[?!.,;:]$/, '').toLowerCase();
    if (knownHosts.has(cand) && !foundHosts.has(cand)) {
      foundHosts.add(cand);
      filters.push({ field: 'host', value: cand, operator: 'equals' });
      descParts.push(`on host '${cand}'`);
    }
  }
  if (foundHosts.size === 0) {
    for (const tok of lower.split(/\s+/)) {
      const clean = tok.replace(/[^a-z0-9._-]/g, '');
      if (clean.length >= 2 && knownHosts.has(clean)) {
        foundHosts.add(clean);
        filters.push({ field: 'host', value: clean, operator: 'equals' });
        descParts.push(`on host '${clean}'`);
        break;
      }
    }
  }

  // ── 4. Severity ───────────────────────────────────────────────────────────
  const isSuspicious = /\b(suspicious|anomal|unusual|weird)\b/.test(lower);
  let foundSeverity = null;
  if (!isSuspicious) {
    for (const [kw, sev] of SEVERITY_KEYWORDS) {
      if (lower.includes(kw)) { foundSeverity = sev; break; }
    }
  }
  if (foundSeverity) {
    filters.push({ field: 'severity', value: foundSeverity, operator: 'equals' });
    descParts.push(`with ${foundSeverity} severity`);
  }
  if (isSuspicious) {
    filters.push({ field: 'severity', value: 'HIGH|CRITICAL', operator: 'in' });
    descParts.push('suspicious/anomalous events (HIGH+CRITICAL)');
  }

  // ── 5. Source ─────────────────────────────────────────────────────────────
  let foundSource = null;
  for (const [kw, src] of SOURCE_KEYWORDS) {
    if (lower.includes(kw)) { foundSource = src; break; }
  }
  if (foundSource) {
    filters.push({ field: 'source', value: foundSource, operator: 'equals' });
    descParts.push(`from ${foundSource} source`);
  }

  // ── 6. Event type ─────────────────────────────────────────────────────────
  let foundEvent = null;
  for (const ep of EVENT_PATTERNS) {
    if (ep.terms.some(t => lower.includes(t))) { foundEvent = ep; break; }
  }
  if (foundEvent) {
    filters.push({ field: foundEvent.field, value: foundEvent.value, operator: foundEvent.operator });
    descParts.push(`${foundEvent.label} events`);
  }

  // ── 7. Time reference ─────────────────────────────────────────────────────
  for (const tr of TIME_REFS) {
    if (tr.patterns.some(p => lower.includes(p))) {
      suggestedTimeRange = { label: tr.label, ms: tr.ms };
      break;
    }
  }

  // ── Build explanation ──────────────────────────────────────────────────────
  const timeDesc = suggestedTimeRange ? ` in the ${suggestedTimeRange.label} window` : '';
  let explanation;
  if (descParts.length === 0 && !suggestedTimeRange) {
    explanation = 'No specific filters detected — showing all logs. Try adding an IP, username, severity, or event type to your query.';
  } else {
    const what = foundEvent ? foundEvent.label : 'log';
    const rest = descParts.filter(p => !p.includes(foundEvent?.label ?? '\x00'));
    explanation = `Looking for ${what} events${rest.length ? ' ' + rest.join(', ') : ''}${timeDesc}.`;
  }

  // ── Build translated query ─────────────────────────────────────────────────
  const qParts = filters
    .filter(f => f.field !== 'destIP' && f.operator !== 'in')
    .map(f => {
      if (f.field === 'sourceIP') return `ip:${f.value}`;
      if (f.operator === 'contains') return `message:${f.value}`;
      return `${f.field}:${f.value}`;
    });
  const translatedQuery = qParts.join(' ');

  return { filters, explanation, translatedQuery, suggestedTimeRange };
}
