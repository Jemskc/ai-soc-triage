// ── Field name aliases ────────────────────────────────────────────────────────
// Multi-word aliases listed first (longest match wins)
const MULTI_WORD_ALIASES = [
  ['event type',  'rule'],
  ['log source',  'source'],
  ['time range',  '__time__'],
  ['source ip',   'sourceIP'],
  ['dest ip',     'destIP'],
  ['dst ip',      'destIP'],
  ['src ip',      'sourceIP'],
];

const FIELD_MAP = {
  // Source IP
  sourceip: 'sourceIP', src_ip: 'sourceIP', srcip: 'sourceIP', src: 'sourceIP',
  // Dest IP
  destip: 'destIP', dest_ip: 'destIP', dstip: 'destIP', dst: 'destIP', dest: 'destIP',
  // User
  user: 'user', username: 'user', account: 'user', usr: 'user',
  // Host
  host: 'host', hostname: 'host', computer: 'host', machine: 'host', device: 'host',
  // Severity
  severity: 'severity', sev: 'severity', level: 'severity',
  // Source
  source: 'source', logsource: 'source',
  // Rule / event type
  rule: 'rule', event: 'rule', eventtype: 'rule',
  // Message
  message: 'message', msg: 'message',
  // Time (special)
  time: '__time__', timerange: '__time__', last: '__time__',
};

// ── Time value resolution ─────────────────────────────────────────────────────
const TIME_VALUES = [
  { patterns: ['15m','15min','15mins','15minute','15minutes'],       label: 'Last 15m', ms: 900_000 },
  { patterns: ['1h','1hr','1hour','60m','60min'],                    label: 'Last 1h',  ms: 3_600_000 },
  { patterns: ['6h','6hr','6hours','6hour'],                         label: 'Last 6h',  ms: 21_600_000 },
  { patterns: ['24h','24hr','1d','1day','today'],                    label: 'Last 24h', ms: 86_400_000 },
  { patterns: ['7d','7days','1w','1week','week'],                    label: 'Last 7d',  ms: 604_800_000 },
];

function resolveTimeValue(val) {
  const v = val.toLowerCase().replace(/\s+/g, '');
  for (const t of TIME_VALUES) {
    if (t.patterns.includes(v)) return t;
  }
  return null;
}

// ── Natural language time references ──────────────────────────────────────────
const NL_TIME_REFS = [
  { patterns: ['last 15 min','past 15 min','just now'],                                     label: 'Last 15m', ms: 900_000 },
  { patterns: ['last hour','past hour','last 1 hour','in the last hour','1 hour ago'],       label: 'Last 1h',  ms: 3_600_000 },
  { patterns: ['last 6 hour','past 6 hour','6 hours ago'],                                  label: 'Last 6h',  ms: 21_600_000 },
  { patterns: ['today','this morning','this afternoon','last 24','24 hours','24h','past 24'],label: 'Last 24h', ms: 86_400_000 },
  { patterns: ['yesterday'],                                                                  label: 'Last 48h', ms: 172_800_000 },
  { patterns: ['this week','last week','7 days','past week','last 7'],                       label: 'Last 7d',  ms: 604_800_000 },
];

// ── NLP patterns ──────────────────────────────────────────────────────────────
const FILLER = new Set(['show','me','find','get','what','all','the','logs','log','where',
  'give','display','list','search','for','from','events','entries','records','in','on','by',
  'did','do','have','has','are','is','any','some','with','and','or','that','a','an','about',
  'recent','latest','please','want','need']);

const SOURCE_KW = [
  ['web proxy','Proxy'],['cloudtrail','CloudTrail'],['cloud','CloudTrail'],['aws','CloudTrail'],
  ['event log','Windows'],['windows','Windows'],['sysmon','Sysmon'],['syslog','Linux'],
  ['linux','Linux'],['firewall','Firewall'],['fw','Firewall'],['proxy','Proxy'],
  ['endpoint','EDR'],['edr','EDR'],
];

const SEV_KW = [
  ['critical','CRITICAL'],['crit','CRITICAL'],['error','CRITICAL'],['errors','CRITICAL'],
  ['warning','HIGH'],['warnings','HIGH'],['high','HIGH'],
  ['medium','MEDIUM'],['med','MEDIUM'],['low','LOW'],
];

const EVENT_PATTERNS = [
  { terms: ['failed login','failed logon','login fail','auth fail','authentication fail','brute force','wrong password','invalid password','4625'], field: 'message', value: 'fail',       operator: 'contains', label: 'failed login' },
  { terms: ['powershell','encoded command','invoke-expression','ps1 '],                                                                             field: 'message', value: 'powershell', operator: 'contains', label: 'PowerShell execution' },
  { terms: ['remote desktop','rdp'],                                                                                                                field: 'message', value: 'rdp',        operator: 'contains', label: 'RDP' },
  { terms: ['privilege escalation','privilege','uac bypass','token imperson'],                                                                      field: 'rule',    value: 'privilege',  operator: 'contains', label: 'privilege escalation' },
  { terms: ['lateral movement','lateral'],                                                                                                          field: 'rule',    value: 'lateral',    operator: 'contains', label: 'lateral movement' },
  { terms: ['dns tunnel','dns query','dns request'],                                                                                                field: 'message', value: 'dns',        operator: 'contains', label: 'DNS' },
  { terms: ['outbound connection','outbound','egress'],                                                                                             field: 'message', value: 'outbound',   operator: 'contains', label: 'outbound connection' },
  { terms: ['login','logon','sign in','sign-in','authenticate','authentication','logged in'],                                                       field: 'message', value: 'login',      operator: 'contains', label: 'login' },
];

// ── Structured query parser ───────────────────────────────────────────────────
function parseStructured(text) {
  let normalized = text.toLowerCase();

  // Replace multi-word aliases with their canonical single token
  for (const [alias, canonical] of MULTI_WORD_ALIASES) {
    normalized = normalized.replace(new RegExp(alias.replace(/ /g, '\\s+'), 'gi'), canonical);
  }

  const filters = [];
  let timeRange = null;

  // Match: token = value  |  token:value  |  token == value
  // Value may be quoted ("some value") or unquoted (no spaces)
  const rx = /(\w+)\s*(?:==|!=|=|:)\s*(?:"([^"]+)"|(\S+))/gi;
  let match;
  while ((match = rx.exec(normalized)) !== null) {
    const key   = match[1].toLowerCase();
    const value = (match[2] || match[3] || '').trim();
    if (!value) continue;

    const field = FIELD_MAP[key];
    if (!field) continue;

    if (field === '__time__') {
      const resolved = resolveTimeValue(value);
      if (resolved) timeRange = resolved;
    } else {
      let finalValue = value;
      let operator   = 'equals';
      if (field === 'severity') finalValue = value.toUpperCase();
      if (field === 'message' || field === 'rule') operator = 'contains';
      // Avoid duplicate filters for same field + value
      if (!filters.some(f => f.field === field && f.value === finalValue)) {
        filters.push({ field, value: finalValue, operator });
      }
    }
  }

  return { filters, timeRange };
}

// ── NLP parser ────────────────────────────────────────────────────────────────
function parseNLP(lower, logs, structuredFields) {
  const knownUsers = new Set();
  const knownHosts = new Set();
  for (const l of logs) {
    if (l.user && l.user !== 'Unknown') knownUsers.add(l.user.toLowerCase());
    if (l.host && l.host !== 'Unknown') knownHosts.add(l.host.toLowerCase());
  }

  const filters = [];
  let timeRange = null;

  // IPs — only if not already captured by structured parser
  if (!structuredFields.has('sourceIP')) {
    const ips = [...lower.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)].map(m => m[1]);
    for (const ip of ips) filters.push({ field: 'sourceIP', value: ip, operator: 'equals' });
  }

  // Usernames
  if (!structuredFields.has('user')) {
    const userRxs = [
      /\buser[:\s]+([a-zA-Z0-9._@-]+)/,
      /\busername[:\s]+([a-zA-Z0-9._@-]+)/,
      /\bdid\s+([a-zA-Z0-9._@-]{3,})\b/,
    ];
    let found = false;
    for (const rx of userRxs) {
      const m = lower.match(rx);
      if (!m) continue;
      const cand = m[1].replace(/[?!.,;:]$/, '');
      if (knownUsers.has(cand)) {
        filters.push({ field: 'user', value: cand, operator: 'equals' });
        found = true; break;
      }
    }
    if (!found) {
      for (const tok of lower.replace(/[^a-z0-9._@-]/g, ' ').split(/\s+/)) {
        if (tok.length >= 3 && !FILLER.has(tok) && knownUsers.has(tok)) {
          filters.push({ field: 'user', value: tok, operator: 'equals' }); break;
        }
      }
    }
  }

  // Hosts
  if (!structuredFields.has('host')) {
    const hostRxs = [
      /\bhost[:\s]+([a-zA-Z0-9._-]+)/,
      /\bmachine[:\s]+([a-zA-Z0-9._-]+)/,
      /\bcomputer[:\s]+([a-zA-Z0-9._-]+)/,
      /\bon\s+((?:WS|PC|DC|SRV|SERVER|HOST)-[a-zA-Z0-9_-]+)/i,
    ];
    let found = false;
    for (const rx of hostRxs) {
      const m = lower.match(rx);
      if (!m) continue;
      const cand = m[1].replace(/[?!.,;:]$/, '').toLowerCase();
      if (knownHosts.has(cand)) {
        filters.push({ field: 'host', value: cand, operator: 'equals' });
        found = true; break;
      }
    }
    if (!found) {
      for (const tok of lower.split(/\s+/)) {
        const clean = tok.replace(/[^a-z0-9._-]/g, '');
        if (clean.length >= 2 && knownHosts.has(clean)) {
          filters.push({ field: 'host', value: clean, operator: 'equals' }); break;
        }
      }
    }
  }

  // Severity
  if (!structuredFields.has('severity')) {
    const suspicious = /\b(suspicious|anomal|unusual|weird)\b/.test(lower);
    if (suspicious) {
      filters.push({ field: 'severity', value: 'HIGH|CRITICAL', operator: 'in' });
    } else {
      for (const [kw, sev] of SEV_KW) {
        if (lower.includes(kw)) { filters.push({ field: 'severity', value: sev, operator: 'equals' }); break; }
      }
    }
  }

  // Source
  if (!structuredFields.has('source')) {
    for (const [kw, src] of SOURCE_KW) {
      if (lower.includes(kw)) { filters.push({ field: 'source', value: src, operator: 'equals' }); break; }
    }
  }

  // Event type
  for (const ep of EVENT_PATTERNS) {
    if (ep.terms.some(t => lower.includes(t))) {
      if (!filters.some(f => f.field === ep.field)) {
        filters.push({ field: ep.field, value: ep.value, operator: ep.operator });
      }
      break;
    }
  }

  // Natural language time
  for (const tr of NL_TIME_REFS) {
    if (tr.patterns.some(p => lower.includes(p))) {
      timeRange = { label: tr.label, ms: tr.ms }; break;
    }
  }

  return { filters, timeRange };
}

// ── Main export ───────────────────────────────────────────────────────────────
export function aiLogSearch(queryText, logs) {
  if (!queryText?.trim()) return { filters: [], translatedQuery: '', suggestedTimeRange: null };

  const lower = queryText.toLowerCase();

  // Step 1: structured parse (field = value, field:value)
  const structured = parseStructured(lower);
  const structuredFields = new Set(structured.filters.map(f => f.field));

  // Step 2: NLP parse on the full text, skipping already-found fields
  const nlp = parseNLP(lower, logs, structuredFields);

  // Step 3: merge — structured takes priority
  const filters = [
    ...structured.filters,
    ...nlp.filters.filter(f => !structuredFields.has(f.field)),
  ];
  const suggestedTimeRange = structured.timeRange || nlp.timeRange || null;

  // Step 4: build translated query string for display
  const translatedQuery = filters
    .filter(f => f.operator !== 'in')
    .map(f => {
      if (f.field === 'sourceIP') return `src_ip:${f.value}`;
      if (f.operator === 'contains') return `${f.field}:"${f.value}"`;
      return `${f.field}:${f.value}`;
    })
    .join(' ');

  return { filters, translatedQuery, suggestedTimeRange };
}
