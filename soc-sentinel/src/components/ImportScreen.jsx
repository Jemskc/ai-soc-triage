import { useState, useRef } from 'react';
import { Shield, Upload, FileText } from 'lucide-react';

export default function ImportScreen({ onImport, onSampleData }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  function handleDrop(e) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onImport(file);
  }

  return (
    <div className="flex-1 flex flex-col items-center justify-center bg-base animate-fadeIn">
      <div className="flex flex-col items-center gap-6 w-full max-w-lg px-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
            <Shield size={24} className="text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-primary">SOC Sentinel</h1>
            <p className="text-muted text-xs">Security Operations Center Dashboard</p>
          </div>
        </div>

        <div
          onDragEnter={() => setDragging(true)}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={`w-full border-2 border-dashed rounded-xl p-12 flex flex-col items-center gap-4 transition-all cursor-pointer ${
            dragging
              ? 'border-blue-400 bg-blue-400/10 shadow-lg shadow-blue-500/20'
              : 'border-border hover:border-blue-500/50 hover:bg-hover'
          }`}
          onClick={() => inputRef.current?.click()}
        >
          <div className={`w-16 h-16 rounded-full flex items-center justify-center transition-colors ${dragging ? 'bg-blue-500/20' : 'bg-card'}`}>
            {dragging ? (
              <FileText size={28} className="text-blue-400" />
            ) : (
              <Upload size={28} className="text-muted" />
            )}
          </div>
          <div className="text-center">
            <p className="text-primary font-medium mb-1">
              {dragging ? 'Drop to import' : 'Load a log file to begin analysis'}
            </p>
            <p className="text-muted text-xs">Drag & drop or click to browse</p>
            <p className="text-muted text-xs mt-1">Supports .json, .csv, .log, .txt</p>
          </div>
          <button
            onClick={e => { e.stopPropagation(); inputRef.current?.click(); }}
            className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <Upload size={14} />
            Import Log File
          </button>
        </div>

        <input
          ref={inputRef}
          type="file"
          accept=".json,.csv,.log,.txt"
          className="hidden"
          onChange={e => { if (e.target.files[0]) onImport(e.target.files[0]); e.target.value = ''; }}
        />

        <button
          onClick={onSampleData}
          className="text-blue-400 hover:text-blue-300 text-sm transition-colors underline underline-offset-2"
        >
          Try with sample data →
        </button>
      </div>
    </div>
  );
}
