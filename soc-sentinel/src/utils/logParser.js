import Papa from 'papaparse';
import { normalizeSeverity } from './severityUtils';

let _idCounter = 1;
function nextId() { return `AL-${String(_idCounter++).padStart(4, '0')}`; }

const FIELD_MAP = {
  timestamp: ['timestamp', '@timestamp', 'time', 'date', 'eventTime', 'event_time', 'datetime', 'TimeGenerated'],
  severity:  ['severity', 'level', 'priority', 'alert_level', 'LogLevel', 'log_level', 'alertLevel', 'Severity'],
  sourceIP:  ['sourceIP', 'src_ip', 'source.ip', 'src', 'clientIP', 'remote_addr', 'client_ip', 'source_ip', 'SourceIP'],
  destIP:    ['destIP', 'dest_ip', 'destination.ip', 'dst', 'dest', 'target_ip'],
  user:      ['user', 'username', 'User', 'account', 'userId', 'user_name', 'Username', 'AccountName'],
  host:      ['host', 'hostname', 'Host', 'computer', 'device', 'ComputerName', 'machine', 'Hostname'],
  message:   ['message', 'msg', 'description', 'event', 'log', 'Message', 'EventMessage', 'details'],
  rule:      ['rule', 'ruleName', 'alert', 'eventType', 'category', 'event_type', 'signature', 'EventID', 'rule_name'],
  source:    ['source', 'sourceName', 'logSource', 'product', 'log_source', 'Source'],
};

function pickField(obj, candidates) {
  for (const k of candidates) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return String(obj[k]);
    const lower = Object.keys(obj).find(ok => ok.toLowerCase() === k.toLowerCase());
    if (lower && obj[lower] !== undefined && obj[lower] !== null && obj[lower] !== '') return String(obj[lower]);
  }
  return '';
}

function normalize(raw, index) {
  const ts = pickField(raw, FIELD_MAP.timestamp) || new Date().toISOString();
  const severityRaw = pickField(raw, FIELD_MAP.severity);
  const severity = normalizeSeverity(severityRaw || inferSeverity(raw));
  const sourceIP = pickField(raw, FIELD_MAP.sourceIP) || extractIP(JSON.stringify(raw)) || 'Unknown';
  const destIP = pickField(raw, FIELD_MAP.destIP) || 'Unknown';
  const user = pickField(raw, FIELD_MAP.user) || 'Unknown';
  const host = pickField(raw, FIELD_MAP.host) || 'Unknown';
  const message = pickField(raw, FIELD_MAP.message) || JSON.stringify(raw);
  const rule = pickField(raw, FIELD_MAP.rule) || `Event-${index}`;
  const source = pickField(raw, FIELD_MAP.source) || 'Log File';
  const mitre = getMitreFromRule(rule, message);
  return {
    id: nextId(),
    timestamp: ts,
    severity,
    sourceIP,
    destIP,
    user,
    host,
    message,
    rule,
    source,
    mitre,
    status: 'open',
    _raw: raw,
  };
}

function inferSeverity(obj) {
  const text = JSON.stringify(obj).toLowerCase();
  if (text.includes('critical') || text.includes('fatal') || text.includes('error')) return 'CRITICAL';
  if (text.includes('warn') || text.includes('high')) return 'HIGH';
  if (text.includes('medium') || text.includes('notice')) return 'MEDIUM';
  return 'LOW';
}

function extractIP(text) {
  const m = text.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
  return m ? m[0] : '';
}

function getMitreFromRule(rule, msg) {
  const text = `${rule} ${msg}`.toLowerCase();
  if (text.includes('brute') || text.includes('login fail') || text.includes('invalid')) return 'T1110.001';
  if (text.includes('powershell') || text.includes('ps1') || text.includes('-enc')) return 'T1059.001';
  if (text.includes('rdp') || text.includes('lateral') || text.includes('wmi')) return 'T1021';
  if (text.includes('privilege') || text.includes('escalat')) return 'T1078';
  if (text.includes('phish') || text.includes('macro')) return 'T1566';
  if (text.includes('exfil') || text.includes('dns tunnel')) return 'T1041';
  return 'T1190';
}

function parseJSON(text) {
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (typeof parsed === 'object' && parsed !== null) return [parsed];
  } catch {}
  const lines = text.split('\n').filter(l => l.trim());
  const entries = [];
  for (const line of lines) {
    try { entries.push(JSON.parse(line)); } catch {}
  }
  return entries;
}

function parseCSV(text) {
  const result = Papa.parse(text, { header: true, skipEmptyLines: true, dynamicTyping: false });
  return result.data || [];
}

const TS_PATTERNS = [
  /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
  /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/,
  /[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/,
  /\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}/,
];

function parsePlainText(text) {
  return text
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      let timestamp = '';
      for (const re of TS_PATTERNS) {
        const m = line.match(re);
        if (m) { timestamp = m[0]; break; }
      }
      const ip = extractIP(line);
      const sevMatch = line.match(/\b(CRITICAL|FATAL|HIGH|WARNING|WARN|MEDIUM|LOW|INFO|ERROR)\b/i);
      const severity = sevMatch ? normalizeSeverity(sevMatch[1]) : 'LOW';
      const userMatch = line.match(/(?:user|username|uid)[=:]\s*(\w+)/i);
      const hostMatch = line.match(/(?:host|hostname)[=:]\s*([\w.-]+)/i);
      return {
        timestamp: timestamp || new Date().toISOString(),
        severity,
        sourceIP: ip || 'Unknown',
        user: userMatch ? userMatch[1] : 'Unknown',
        host: hostMatch ? hostMatch[1] : 'Unknown',
        message: line,
        raw: line,
      };
    });
}

export async function parseLogFile(file, onProgress) {
  _idCounter = 1;
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const text = e.target.result;
        const ext = file.name.split('.').pop().toLowerCase();
        let raw = [];
        if (ext === 'json') raw = parseJSON(text);
        else if (ext === 'csv') raw = parseCSV(text);
        else raw = parsePlainText(text);
        if (!raw.length) { reject(new Error('No records found')); return; }
        const CHUNK = 500;
        const results = [];
        let i = 0;
        function processChunk() {
          const end = Math.min(i + CHUNK, raw.length);
          for (; i < end; i++) {
            results.push(normalize(raw[i], i));
          }
          onProgress?.(i, raw.length);
          if (i < raw.length) setTimeout(processChunk, 0);
          else resolve(results);
        }
        processChunk();
      } catch (err) {
        reject(err);
      }
    };
    reader.onerror = () => reject(new Error('File read error'));
    reader.readAsText(file);
  });
}

export function loadMockData(mockEntries) {
  _idCounter = 1;
  return mockEntries.map((e, i) => normalize(e, i));
}
