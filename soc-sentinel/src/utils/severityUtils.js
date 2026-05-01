export const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function normalizeSeverity(raw) {
  if (!raw) return 'LOW';
  const v = String(raw).toUpperCase().trim();
  if (['CRITICAL', 'FATAL', 'ALERT', 'ERROR', 'EMERGENCY'].includes(v)) return 'CRITICAL';
  if (['HIGH', 'WARNING', 'WARN', 'SEVERE'].includes(v)) return 'HIGH';
  if (['MEDIUM', 'MODERATE', 'NOTICE'].includes(v)) return 'MEDIUM';
  if (['LOW', 'INFO', 'INFORMATION', 'DEBUG', 'TRACE'].includes(v)) return 'LOW';
  return 'LOW';
}

export function severityColor(sev) {
  switch (sev) {
    case 'CRITICAL': return '#ef4444';
    case 'HIGH':     return '#f97316';
    case 'MEDIUM':   return '#eab308';
    case 'LOW':      return '#3b82f6';
    default:         return '#64748b';
  }
}

export function severityBg(sev) {
  switch (sev) {
    case 'CRITICAL': return 'bg-red-500 text-white';
    case 'HIGH':     return 'bg-orange-500 text-white';
    case 'MEDIUM':   return 'bg-yellow-500 text-black';
    case 'LOW':      return 'bg-blue-500 text-white';
    default:         return 'bg-gray-600 text-white';
  }
}

export function severityOrder(sev) {
  return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[sev] ?? 4;
}
