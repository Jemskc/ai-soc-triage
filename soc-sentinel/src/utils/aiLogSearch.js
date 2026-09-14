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
  // Listed before the generic login pattern below. "NTLM authentication" used
  // to match that pattern and come out as message contains "login" — the one
  // word that made the question specific was discarded, and the search
  // returned every successful logon in the estate.
  { terms: ['kerberos'],                                                                                                                            field: 'message', value: 'kerberos',   operator: 'contains', label: 'Kerberos' },
  { terms: ['ntlm'],                                                                                                                                field: 'message', value: 'ntlm',       operator: 'contains', label: 'NTLM' },
  { terms: ['negotiate'],                                                                                                                           field: 'message', value: 'negotiate',  operator: 'contains', label: 'Negotiate' },
  { terms: ['logoff','log off','logout','sign out'],                                                                                                field: 'message', value: 'logoff',     operator: 'contains', label: 'logoff' },
  { terms: ['login','logon','sign in','sign-in','authenticate','authentication','logged in'],                                                       field: 'message', value: 'logon',      operator: 'contains', label: 'logon' },
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
      let finalField = field;
      if (field === 'severity') finalValue = value.toUpperCase();
      // "event type = 4624" resolves to the rule field, where it became a
      // substring search for "4624" inside a rule name. A number there is an
      // event id and should be matched as one.
      if (field === 'rule' && /^\d{3,5}$/.test(value)) finalField = 'eventId';
      else if (field === 'message' || field === 'rule') operator = 'contains';
      // Avoid duplicate filters for same field + value
      if (!filters.some(f => f.field === finalField && f.value === finalValue)) {
        filters.push({ field: finalField, value: finalValue, operator });
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
      /\buser[:\s]+([a-zA-Z0-9._@$-]+)/,
      /\busername[:\s]+([a-zA-Z0-9._@$-]+)/,
      /\baccount[:\s]+([a-zA-Z0-9._@$-]+)/,
      /\bdid\s+([a-zA-Z0-9._@$-]{3,})\b/,
    ];
    let found = false;
    for (const rx of userRxs) {
      const m = lower.match(rx);
      if (!m) continue;
      const cand = m[1].replace(/[?!.,;:]$/, '');
      // A named account is taken at its word.
      //
      // This used to require the name to appear in `logs` — the 500 rows the
      // browser happened to be holding. Asking for "user U160" while looking
      // at page one of a 20,200-row corpus therefore produced no filter at
      // all, and the search silently returned everything. The server has the
      // corpus; it can decide whether the account exists.
      if (knownUsers.has(cand) || /^[a-z]\d+\$?$/.test(cand) || cand.length >= 3) {
        filters.push({ field: 'user', value: cand, operator: 'equals' });
        found = true; break;
      }
    }
    if (!found) {
      for (const tok of lower.replace(/[^a-z0-9._@-]/g, ' ').split(/\s+/)) {
        if (tok.length >= 3 && !FILLER.has(tok) && knownUsers.has(tok)) {
          filters.push({ field: 'user', value: tok, operator: 'equals' });
          found = true; break;
        }
      }
    }
    // U160, U3635 — accounts in this corpus. Machine accounts end in $.
    if (!found) {
      const bare = lower.match(/\bu\d{1,6}\$?\b/);
      if (bare) filters.push({ field: 'user', value: bare[0], operator: 'equals' });
    }
  }

  // Hosts
  if (!structuredFields.has('host')) {
    const hostRxs = [
      /\bhost[:\s]+([a-zA-Z0-9._-]+)/,
      /\bmachine[:\s]+([a-zA-Z0-9._-]+)/,
      /\bcomputer[:\s]+([a-zA-Z0-9._-]+)/,
      /\bon\s+((?:WS|PC|DC|SRV|SERVER|HOST)-[a-zA-Z0-9_-]+)/i,
      // C1691, C12682 — how this corpus names machines. The patterns above
      // only knew WS-/PC-/DC- style names from the sample data.
      /\b(?:host|on|from|to)\s+(c\d{1,6})\b/,
    ];
    let found = false;
    for (const rx of hostRxs) {
      const m = lower.match(rx);
      if (!m) continue;
      const cand = m[1].replace(/[?!.,;:]$/, '').toLowerCase();
      if (knownHosts.has(cand) || /^c\d{1,6}$/.test(cand) || cand.length >= 2) {
        filters.push({ field: 'host', value: cand, operator: 'equals' });
        found = true; break;
      }
    }
    if (!found) {
      for (const tok of lower.split(/\s+/)) {
        const clean = tok.replace(/[^a-z0-9._-]/g, '');
        if (clean.length >= 2 && knownHosts.has(clean)) {
          filters.push({ field: 'host', value: clean, operator: 'equals' });
          found = true; break;
        }
      }
    }
    // A bare "C1588" in the query is a machine name in this corpus. Without
    // this, "show me everything from C1588" produced no filter whatsoever.
    if (!found) {
      const bare = lower.match(/\bc\d{2,6}\b/);
      if (bare) filters.push({ field: 'host', value: bare[0], operator: 'equals' });
    }
  }

  // Windows event ids — "event 4624", "event id 4688", or a bare 4-digit code
  // that is not part of a date or a time.
  if (!structuredFields.has('rule')) {
    const idm = lower.match(/\bevent(?:\s*id)?[:\s]+(\d{3,5})\b/)
      || (/\b\d{4}\b/.test(lower.replace(/\d{4}[-/]\d{1,2}[-/]\d{1,2}/g, '')
                              .replace(/\d{1,2}:\d{2}(:\d{2})?/g, ''))
          ? lower.replace(/\d{4}[-/]\d{1,2}[-/]\d{1,2}/g, '')
                 .replace(/\d{1,2}:\d{2}(:\d{2})?/g, '').match(/\b(\d{4})\b/)
          : null);
    if (idm) filters.push({ field: 'eventId', value: idm[1], operator: 'equals' });
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


// ── Absolute time windows ─────────────────────────────────────────────────────
// Everything above resolves time relative to *now*. That is useless against a
// corpus recorded in 2015: "last 24h" over LANL authentication data matches
// nothing at all, and asking for a window between two clock times had no
// parse path whatsoever — the phrase fell through to the keyword matcher and
// the search returned the whole estate.

const MONTHS = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6,
  jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12,
};

// 2015-01-01, 2015/01/01, 01-01-2015, "1 jan 2015", "jan 1 2015"
const DATE_RE = [
  /(\d{4})[-/](\d{1,2})[-/](\d{1,2})/,
  /(\d{1,2})[-/](\d{1,2})[-/](\d{4})/,
];
const TIME_RE = /(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(am|pm)?/;

function pad(n) { return String(n).padStart(2, '0'); }

/** One date and/or clock time out of a fragment, as "YYYY-MM-DD HH:MM:SS". */
function parseMoment(fragment, fallbackDate, endOfRange) {
  if (!fragment) return null;
  const text = fragment.trim();
  let y = null, mo = null, d = null;

  let m = text.match(DATE_RE[0]);
  if (m) { [, y, mo, d] = m.map(Number); }
  if (!y) {
    m = text.match(DATE_RE[1]);
    if (m) { d = +m[1]; mo = +m[2]; y = +m[3]; }
  }
  if (!y) {
    // "3 jan 2015" / "jan 3 2015" / "jan 3"
    const name = text.match(/\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b/);
    if (name) {
      mo = MONTHS[name[1]];
      const dayBefore = text.match(new RegExp('(\\d{1,2})\\s*' + name[1]));
      const dayAfter = text.match(new RegExp(name[1] + '[a-z]*\\s*(\\d{1,2})'));
      d = Number((dayBefore || dayAfter || [])[1]) || 1;
      const year = text.match(/\b(19|20)\d{2}\b/);
      y = year ? Number(year[0]) : null;
    }
  }

  const t = text.match(TIME_RE);
  let hh = null, mi = 0, ss = null;
  if (t) {
    hh = Number(t[1]); mi = Number(t[2]); ss = t[3] === undefined ? null : Number(t[3]);
    if (t[4] === 'pm' && hh < 12) hh += 12;
    if (t[4] === 'am' && hh === 12) hh = 0;
  }

  if (!y && fallbackDate) { [y, mo, d] = fallbackDate; }
  if (!y) return null;

  // "to 3pm" means the end of 15:00:59, not 15:00:00 — an inclusive upper
  // bound is what a person means by "between 2 and 3".
  if (hh === null) { hh = endOfRange ? 23 : 0; mi = endOfRange ? 59 : 0; ss = endOfRange ? 59 : 0; }
  else if (ss === null) { ss = endOfRange ? 59 : 0; }

  return { iso: `${y}-${pad(mo || 1)}-${pad(d || 1)} ${pad(hh)}:${pad(mi)}:${pad(ss)}`,
           date: [y, mo || 1, d || 1] };
}

/**
 * An explicit window out of the query, if there is one.
 * Handles "from X to Y", "between X and Y", "after X", "before X", "on X".
 */
export function parseAbsoluteWindow(lower) {
  const range = lower.match(
    /(?:from|between)\s+(.+?)\s+(?:to|until|till|and|-|–)\s+(.+?)(?:$|[,.;])/);
  if (range) {
    // The end fragment often omits the date ("from 2015-01-01 01:00 to 03:00"),
    // so it inherits the start's day rather than failing to parse.
    const a = parseMoment(range[1], null, false);
    const b = parseMoment(range[2], a?.date, true);
    if (a || b) {
      return { from: a?.iso || null, to: b?.iso || null,
               label: `${a?.iso || '…'} → ${b?.iso || '…'}` };
    }
  }

  const after = lower.match(/(?:after|since|newer than)\s+(.+?)(?:$|[,.;])/);
  if (after) {
    const a = parseMoment(after[1], null, false);
    if (a) return { from: a.iso, to: null, label: `after ${a.iso}` };
  }

  const before = lower.match(/(?:before|until|older than)\s+(.+?)(?:$|[,.;])/);
  if (before) {
    const b = parseMoment(before[1], null, true);
    if (b) return { from: null, to: b.iso, label: `before ${b.iso}` };
  }

  const on = lower.match(/\bon\s+(.+?)(?:$|[,.;])/);
  if (on) {
    const a = parseMoment(on[1], null, false);
    const b = parseMoment(on[1], null, true);
    if (a && b) return { from: a.iso, to: b.iso, label: `on ${a.iso.slice(0, 10)}` };
  }

  // A bare date with no preposition: "2015-01-01 logins".
  const bare = parseMoment(lower, null, false);
  if (bare && /\d{4}[-/]\d{1,2}[-/]\d{1,2}/.test(lower)) {
    const end = parseMoment(lower, null, true);
    return { from: bare.iso, to: end.iso, label: `on ${bare.iso.slice(0, 10)}` };
  }
  return null;
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
  // An explicit window wins over a relative one: someone who names two clock
  // times has said exactly what they want.
  const absoluteWindow = parseAbsoluteWindow(lower);

  // Step 4: build translated query string for display
  const translatedQuery = filters
    .filter(f => f.operator !== 'in')
    .map(f => {
      if (f.field === 'sourceIP') return `src_ip:${f.value}`;
      if (f.operator === 'contains') return `${f.field}:"${f.value}"`;
      return `${f.field}:${f.value}`;
    })
    .join(' ');

  return { filters, translatedQuery, suggestedTimeRange, absoluteWindow };
}
