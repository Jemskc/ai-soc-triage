import Papa from 'papaparse';

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportJSON(data, filename = 'logs_export.json') {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  download(blob, filename);
}

export function exportCSV(data, filename = 'logs_export.csv') {
  const csv = Papa.unparse(data.map(row => {
    const { _raw, ...rest } = row;
    return rest;
  }));
  const blob = new Blob([csv], { type: 'text/csv' });
  download(blob, filename);
}

export function exportSummary(logs, fileInfo) {
  const sev = counts => ({
    critical: logs.filter(l => l.severity === 'CRITICAL').length,
    high: logs.filter(l => l.severity === 'HIGH').length,
    medium: logs.filter(l => l.severity === 'MEDIUM').length,
    low: logs.filter(l => l.severity === 'LOW').length,
  });

  const timestamps = logs.map(l => l.timestamp).filter(Boolean).sort();
  const topIPs = getTopN(logs.map(l => l.sourceIP), 10);
  const topUsers = getTopN(logs.map(l => l.user), 10);

  const summary = {
    filename: fileInfo?.name ?? 'unknown',
    importedAt: fileInfo?.importedAt ?? new Date().toISOString(),
    totalLogs: logs.length,
    ...sev(),
    uniqueIPs: new Set(logs.map(l => l.sourceIP)).size,
    uniqueUsers: new Set(logs.map(l => l.user)).size,
    uniqueHosts: new Set(logs.map(l => l.host)).size,
    topSourceIPs: topIPs,
    topUsers,
    timeRange: { start: timestamps[0] ?? null, end: timestamps[timestamps.length - 1] ?? null },
  };
  const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' });
  download(blob, `${(fileInfo?.name ?? 'analysis').replace(/\.[^.]+$/, '')}_summary.json`);
}

function getTopN(arr, n) {
  const counts = {};
  for (const v of arr) counts[v] = (counts[v] || 0) + 1;
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}
