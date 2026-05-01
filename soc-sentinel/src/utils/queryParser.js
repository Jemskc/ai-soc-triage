const FIELD_MAP = {
  source:   l => l.source,
  user:     l => l.user,
  ip:       l => l.sourceIP,
  severity: l => l.severity,
  host:     l => l.host,
  event_id: l => l.rule,
  message:  l => l.message,
};

export function parseQuery(queryString) {
  if (!queryString?.trim()) return [];
  const conditions = [];
  const re = /(\w+):"([^"]+)"|(\w+):(\S+)/g;
  let m;
  while ((m = re.exec(queryString)) !== null) {
    const field = (m[1] || m[3]).toLowerCase();
    const value = (m[2] || m[4]).toLowerCase();
    if (field in FIELD_MAP) conditions.push({ field, value });
  }
  return conditions;
}

export function applyQuery(logs, conditions) {
  if (!conditions.length) return logs;
  return logs.filter(log =>
    conditions.every(({ field, value }) => {
      const getter = FIELD_MAP[field];
      if (!getter) return true;
      const fieldVal = String(getter(log) ?? '').toLowerCase();
      return field === 'message' ? fieldVal.includes(value) : fieldVal === value;
    })
  );
}
