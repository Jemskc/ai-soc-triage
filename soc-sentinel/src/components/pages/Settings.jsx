export default function Settings({ fileInfo, onImport }) {
  return (
    <div className="animate-fadeIn space-y-4">
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-primary text-sm font-medium mb-3">Active Log Sources</h3>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left text-muted py-2 font-medium">Source</th>
              <th className="text-left text-muted py-2 font-medium">Type</th>
              <th className="text-left text-muted py-2 font-medium">Status</th>
              <th className="text-right text-muted py-2 font-medium">Events</th>
            </tr>
          </thead>
          <tbody>
            {fileInfo ? (
              <tr className="border-b border-border">
                <td className="py-2 text-primary font-mono">{fileInfo.name}</td>
                <td className="py-2 text-muted">File Import</td>
                <td className="py-2"><span className="text-green-400 text-[10px]">● Active</span></td>
                <td className="py-2 text-right text-muted">{fileInfo.count?.toLocaleString() ?? '—'}</td>
              </tr>
            ) : (
              <tr><td colSpan={4} className="py-6 text-center text-muted">No log sources connected</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <h3 className="text-primary text-sm font-medium">Import Settings</h3>
        <p className="text-muted text-xs">
          SOC Sentinel supports .json, .csv, .log, and .txt log files. Files are processed locally in your browser — no data is sent to any server.
        </p>
        <div className="grid grid-cols-2 gap-3 text-xs">
          {[
            ['JSON / NDJSON', '.json arrays or newline-delimited objects'],
            ['CSV', 'Header row required; any delimiter auto-detected'],
            ['Plain Text Log', 'Timestamp, IP, severity extracted by regex'],
            ['Max Rows', 'No hard limit — large files chunk-processed to avoid UI blocking'],
          ].map(([k, v]) => (
            <div key={k} className="bg-panel rounded p-3">
              <p className="text-primary font-medium mb-1">{k}</p>
              <p className="text-muted">{v}</p>
            </div>
          ))}
        </div>
        <button
          onClick={onImport}
          className="mt-2 px-4 py-2 bg-blue-600 rounded text-xs text-white hover:bg-blue-500 transition-colors"
        >
          Import New Log File
        </button>
      </div>

      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-primary text-sm font-medium mb-3">About SOC Sentinel</h3>
        <div className="text-xs text-muted space-y-1">
          <p>Version: 1.0.0</p>
          <p>Built with React + Vite + Tailwind CSS + Recharts</p>
          <p>All processing runs locally in your browser. Zero external API calls.</p>
          <p className="text-blue-400 mt-2">Blue Team AI Project — Cybersecurity Portfolio</p>
        </div>
      </div>
    </div>
  );
}
