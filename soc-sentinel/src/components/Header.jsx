import { useState, useRef } from 'react';
import { Shield, Upload, Download, Search, Bell, Settings, Menu, X, ChevronDown, Moon, Sun } from 'lucide-react';
import { exportJSON, exportCSV, exportSummary } from '../utils/logExporter';

export default function Header({ logs, fileInfo, onImport, onSearch, sidebarOpen, onToggleSidebar, theme, onToggleTheme }) {
  const [showExport, setShowExport] = useState(false);
  const [exportMode, setExportMode] = useState('json');
  const [query, setQuery] = useState('');
  const inputRef = useRef(null);
  const fileRef = useRef(null);

  const loaded = fileInfo !== null;

  function handleExport() {
    if (exportMode === 'json') exportJSON(logs, `${fileInfo?.name ?? 'logs'}_export.json`);
    else if (exportMode === 'csv') exportCSV(logs, `${fileInfo?.name ?? 'logs'}_export.csv`);
    else if (exportMode === 'filtered') exportCSV(logs, `${fileInfo?.name ?? 'logs'}_filtered.csv`);
    else exportSummary(logs, fileInfo);
    setShowExport(false);
  }

  return (
    <header className="h-12 flex items-center gap-3 px-3 border-b border-border bg-panel shrink-0 relative z-20">
      <button onClick={onToggleSidebar} className="text-muted hover:text-primary transition-colors p-1 rounded">
        {sidebarOpen ? <X size={16} /> : <Menu size={16} />}
      </button>

      <div className="flex items-center gap-2 shrink-0">
        <Shield size={16} className="text-blue-400" />
        <span className="text-primary font-semibold text-sm">SOC Sentinel</span>
      </div>

      {loaded && (
        <div className="flex items-center gap-2 ml-1">
          <span className="text-muted text-xs font-mono bg-hover px-2 py-1 rounded border border-border truncate max-w-[200px]">
            {fileInfo.name}
          </span>
          <span className="text-muted text-xs">{logs.length.toLocaleString()} records</span>
          <span className="text-[10px] bg-green-500/20 text-green-400 border border-green-500/30 px-2 py-0.5 rounded-full font-medium">
            Loaded
          </span>
        </div>
      )}

      <div className="flex-1 max-w-md mx-auto">
        <div className="relative">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && (onSearch(query), setQuery(''))}
            placeholder={loaded ? 'Search logs... (Enter)' : 'Load a file to search'}
            disabled={!loaded}
            className="w-full bg-hover border border-border rounded pl-8 pr-3 py-1.5 text-xs text-primary placeholder-muted focus:outline-none focus:border-blue-500 transition-colors disabled:opacity-40"
          />
        </div>
      </div>

      <div className="flex items-center gap-1.5 ml-auto">
        <button onClick={() => fileRef.current?.click()}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-hover border border-border rounded text-xs text-primary hover:border-blue-500 transition-colors">
          <Upload size={12} />
          Import
        </button>

        {loaded && (
          <div className="relative">
            <button
              onClick={() => setShowExport(p => !p)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors"
            >
              <Download size={12} />
              Export
              <ChevronDown size={10} />
            </button>
            {showExport && (
              <div className="absolute right-0 top-full mt-1 w-56 bg-card border border-border rounded-lg shadow-xl z-50 overflow-hidden">
                <div className="p-2 border-b border-border text-muted text-[10px] uppercase tracking-wider px-3">Export current view</div>
                {[
                  ['json', 'All logs (.json)'],
                  ['csv', 'All logs (.csv)'],
                  ['filtered', 'Filtered alerts only (.csv)'],
                  ['summary', 'Analysis summary (.json)'],
                ].map(([mode, label]) => (
                  <label key={mode} className="flex items-center gap-2 px-3 py-2 hover:bg-hover cursor-pointer text-xs text-primary transition-colors">
                    <input type="radio" name="export" value={mode} checked={exportMode === mode} onChange={() => setExportMode(mode)} className="accent-blue-500" />
                    {label}
                  </label>
                ))}
                <div className="p-2 border-t border-border">
                  <button onClick={handleExport} className="w-full py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-xs text-white transition-colors">
                    Download
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        <button onClick={onToggleTheme} className="p-2 text-muted hover:text-primary transition-colors" title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>
        <button className="p-2 text-muted hover:text-primary transition-colors"><Bell size={14} /></button>
        <button className="p-2 text-muted hover:text-primary transition-colors"><Settings size={14} /></button>
        <div className="flex items-center gap-2 ml-1 pl-2 border-l border-border">
          <div className="w-6 h-6 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
            <span className="text-blue-400 text-[10px] font-bold">SA</span>
          </div>
          <span className="text-primary text-xs hidden xl:block">SOC Analyst</span>
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse2" />
        </div>
      </div>

      <input
        ref={fileRef}
        type="file"
        accept=".json,.csv,.log,.txt"
        className="hidden"
        onChange={e => { if (e.target.files[0]) onImport(e.target.files[0]); e.target.value = ''; }}
      />
    </header>
  );
}
