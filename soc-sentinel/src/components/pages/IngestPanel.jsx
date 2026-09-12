import { useRef, useState } from 'react';
import { Upload, Server, FileText, Play, Loader, CheckCircle2 } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

/**
 * Where logs get into the system.
 *
 * Two routes, because they do different things and conflating them confused
 * the previous UI: a client-side file import for a quick look at your own
 * logs, and a server-side pipeline run that puts data through the funnel and
 * the agents. Only the second produces AI analysis.
 */
export default function IngestPanel({ onImport, onSampleData, fileInfo }) {
  const fileRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [budget, setBudget] = useState(40);
  const { startAnalysis, isRunning, job, status, metrics, isReady } = useAnalysis();

  function handleDrop(e) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onImport(file);
  }

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      {/* Route 1 — server-side pipeline. This is the one that runs the AI. */}
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
          <Server size={14} className="text-blue-400" />
          <span className="text-primary text-sm font-medium">Analyse server-side telemetry</span>
          <span className="ml-auto text-muted text-[10px] uppercase tracking-wider">
            runs the funnel + agents
          </span>
        </div>
        <div className="p-4 space-y-3">
          <p className="text-muted text-xs leading-relaxed">
            Runs the full pipeline over the telemetry on the server: streaming,
            detection rules, statistical and UEBA scoring, correlation, then the
            agent investigation on the highest-ranked cases. This is the only
            route that produces AI analysis.
          </p>

          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-muted text-xs">AI budget</label>
            <input
              type="number"
              min={1}
              max={200}
              value={budget}
              onChange={e => setBudget(Number(e.target.value))}
              disabled={isRunning}
              className="w-20 bg-panel border border-border rounded px-2 py-1 text-xs text-primary focus:outline-none focus:border-blue-500 disabled:opacity-50"
            />
            <span className="text-muted text-[10px]">
              cases sent to the agents; the rest are ranked below the line and recorded
            </span>
          </div>

          <button
            onClick={() => startAnalysis({ ai_budget: budget })}
            disabled={isRunning || status === 'offline'}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-blue-500 hover:bg-blue-600 disabled:opacity-40 disabled:hover:bg-blue-500 text-white text-xs font-medium transition-colors"
          >
            {isRunning ? <Loader size={12} className="animate-spin" /> : <Play size={12} />}
            {isRunning ? 'Analysis running…' : 'Run analysis'}
          </button>

          {status === 'offline' && (
            <p className="text-red-400 text-[11px]">
              Backend unreachable — the pipeline runs on the server, so this needs the API up.
            </p>
          )}

          {isRunning && job && (
            <div className="space-y-1.5">
              <div className="h-1 bg-hover rounded-full overflow-hidden">
                <div className="h-full bg-blue-500 rounded-full transition-all"
                     style={{ width: `${job.percent || 0}%` }} />
              </div>
              <p className="text-muted text-[11px]">{job.message}</p>
            </div>
          )}

          {isReady && metrics && !isRunning && (
            <div className="flex items-center gap-2 text-[11px] text-emerald-400">
              <CheckCircle2 size={12} />
              {metrics.events_ingested?.toLocaleString()} events analysed →{' '}
              {metrics.incidents} incidents
            </div>
          )}
        </div>
      </div>

      {/* Route 2 — client-side file view. No AI; be explicit about that. */}
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
          <Upload size={14} className="text-blue-400" />
          <span className="text-primary text-sm font-medium">Upload a log file</span>
          <span className="ml-auto text-muted text-[10px] uppercase tracking-wider">
            browser-side view only
          </span>
        </div>
        <div className="p-4 space-y-3">
          <div
            onDragOver={e => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
              dragging ? 'border-blue-500 bg-blue-500/5' : 'border-border hover:border-blue-500/50'
            }`}
          >
            <Upload size={22} className="mx-auto text-muted mb-2" />
            <p className="text-primary text-xs font-medium">
              Drop a log file here, or click to browse
            </p>
            <p className="text-muted text-[10px] mt-1">JSON, CSV, or plain text</p>
          </div>

          <input
            ref={fileRef}
            type="file"
            accept=".json,.csv,.log,.txt"
            className="hidden"
            onChange={e => { if (e.target.files[0]) onImport(e.target.files[0]); e.target.value = ''; }}
          />

          <div className="flex items-center gap-2">
            <button
              onClick={onSampleData}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-border text-muted hover:text-primary text-xs transition-colors"
            >
              <FileText size={11} /> Load sample data
            </button>
            {fileInfo && (
              <span className="text-muted text-[11px]">
                Loaded: {fileInfo.name} ({fileInfo.count?.toLocaleString()} records)
              </span>
            )}
          </div>

          <p className="text-muted text-[10px] leading-relaxed">
            An uploaded file is parsed in your browser and shown in the log views.
            It does not reach the server, so it is not scored by the funnel and
            gets no AI analysis — use the option above for that.
          </p>
        </div>
      </div>
    </div>
  );
}
