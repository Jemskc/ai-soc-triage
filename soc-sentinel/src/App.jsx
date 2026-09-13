import { useState, useCallback, useEffect } from 'react';
import { parseLogFile, loadMockData } from './utils/logParser';
import { MOCK_LOGS } from './data/mockData';

import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Footer from './components/Footer';
import AIPanel from './components/AIPanel';
import ImportScreen from './components/ImportScreen';


import AlertsPage from './components/alerts/AlertsPage';
import Settings from './components/pages/Settings';

import { AlertTriangle, Shield, Globe, Users, Loader } from 'lucide-react';

import { AnalysisProvider, useAnalysis } from './context/AnalysisContext';
import AnalysisProgress, { DataSourceBadge } from './components/AnalysisProgress';
import ErrorBoundary from './components/ErrorBoundary';
import ApiKeyGate from './components/ApiKeyGate';
import { NAV_LABELS } from './data/navConfig';
import { api } from './utils/api';
import AISituationReport from './components/overview/AISituationReport';
import AnalysisCoverage from './components/AnalysisCoverage';
import LiveAgentActivity from './components/LiveAgentActivity';
import QueueStatus from './components/QueueStatus';
import LiveLogs from './components/pages/LiveLogs';
import EmailAnalysis from './pages/EmailAnalysis';
import AIInvestigation from './components/pages/AIInvestigation';
import EvidenceGraph from './components/pages/EvidenceGraph';
import ResponsePage from './components/pages/ResponsePage';
import AuditLog from './components/pages/AuditLog';
import DetectionEngineering from './components/pages/DetectionEngineering';
import IngestPanel from './components/pages/IngestPanel';
import AnalystQuestions from './components/pages/AnalystQuestions';

function LoadingOverlay({ progress, total }) {
  const pct = total > 0 ? Math.round((progress / total) * 100) : 0;
  return (
    <div className="fixed inset-0 bg-base/90 flex flex-col items-center justify-center z-50 gap-4">
      <Loader size={32} className="text-blue-400 animate-spin" />
      <p className="text-primary text-sm font-medium">Parsing log file...</p>
      <p className="text-muted text-xs">{progress.toLocaleString()} records processed</p>
      <div className="w-48 h-1.5 bg-hover rounded-full overflow-hidden">
        <div className="h-full bg-blue-500 rounded-full transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Toast({ message, type = 'error' }) {
  return (
    <div className={`fixed bottom-14 left-1/2 -translate-x-1/2 z-50 px-4 py-2 rounded-lg border text-sm font-medium shadow-xl animate-fadeIn ${
      type === 'error' ? 'bg-red-500/20 border-red-500/50 text-red-400' : 'bg-green-500/20 border-green-500/50 text-green-400'
    }`}>
      {message}
    </div>
  );
}

export default function App() {
  // The provider owns the AI analysis bundle that every tab reads from.
  // Raw logs are passed as the fallback so the dashboard still renders (clearly
  // badged as demo data) when the analysis backend is unreachable.
  return (
    <AnalysisProvider fallbackLogs={MOCK_LOGS}>
      <Dashboard />
    </AnalysisProvider>
  );
}

function Dashboard() {
  const { incidentsByUrgency, isReady, events: analysisEvents, metrics, status, error } = useAnalysis();
  const [logs, setLogs] = useState(null);
  const [fileInfo, setFileInfo] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [activeNav, setActiveNav] = useState('logs');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [loading, setLoading] = useState(false);
  const [loadProgress, setLoadProgress] = useState({ done: 0, total: 0 });
  const [toast, setToast] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  // Which incident the AI / Evidence / Response tabs are focused on, so moving
  // between them keeps the same case in view.
  const [focusedIncident, setFocusedIncident] = useState(null);
  const [theme, setTheme] = useState(() => localStorage.getItem('soc-theme') || 'dark');

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    localStorage.setItem('soc-theme', theme);
  }, [theme]);

  function showToast(msg, type = 'error') {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  }

  function handleSelectAlert(alert) {
    setSelectedAlert(alert);
    setSelectedLog(null);
    setSelectedEmail(null);
  }

  function handleSelectLog(log) {
    setSelectedLog(log);
    setSelectedAlert(null);
    setSelectedEmail(null);
  }

  function handleSelectEmail(email) {
    setSelectedEmail(email);
    setSelectedAlert(null);
    setSelectedLog(null);
  }

  const handleImport = useCallback(async file => {
    setLoading(true);
    setLoadProgress({ done: 0, total: 0 });
    try {
      const parsed = await parseLogFile(file, (done, total) => setLoadProgress({ done, total }));
      setLogs(parsed);
      setFileInfo({ name: file.name, size: file.size, importedAt: new Date().toISOString(), count: parsed.length });
      setSelectedAlert(null);
      setSelectedLog(null);
      setActiveNav('logs');

      // Send it to the server as well as showing it. Without this the AI never
      // sees an imported file, which is what made importing appear to succeed
      // and change nothing.
      try {
        const accepted = await api.ingestBatched(
          parsed, file.name,
          (done, total) => setLoadProgress({ done, total }),
        );
        showToast(
          `${parsed.length.toLocaleString()} records from ${file.name} — ` +
          `${accepted.toLocaleString()} sent for analysis`, 'success');
      } catch (err) {
        // The viewer still works; be explicit that the AI will not see this.
        showToast(
          `Loaded ${parsed.length.toLocaleString()} records into the viewer, but the ` +
          `server rejected them (${err.message}). The AI will not analyse this file.`);
      }
    } catch (err) {
      // Show what actually went wrong. This used to replace every failure with
      // "Could not parse file", including the size guard's own explanation of
      // why a 274MB file cannot be read in a browser and what to use instead —
      // so the one message written to be useful was the one thrown away.
      showToast(
        err?.message
          ? `Import failed: ${err.message}`
          : 'Could not parse file. Try JSON, JSONL, CSV, or plain text log format.');
    } finally {
      setLoading(false);
    }
  }, []);

  function handleSampleData() {
    const parsed = loadMockData(MOCK_LOGS);
    setLogs(parsed);
    setFileInfo({ name: 'sample-logs.json', size: 0, importedAt: new Date().toISOString(), count: parsed.length });
    setSelectedAlert(null);
    setSelectedLog(null);
    setActiveNav('logs');
  }

  function handleSearch(query) {
    if (!query.trim()) return;
    setSearchQuery(query);
    setActiveNav('alerts');
  }

  // AI output references incidents by id; every tab that shows one links back
  // to its verdict in the Alerts view.
  function jumpToIncident(incidentId) {
    const match = incidentsByUrgency.find(i => i.incident_id === incidentId);
    if (!match) return;
    handleSelectAlert({ ...match, id: match.incident_id });
    setFocusedIncident(incidentId);
    setSearchQuery('');
    setActiveNav('alerts');
  }

  // A completed backend analysis is enough to show the dashboard: the tabs
  // render from the analysis bundle, not from a locally parsed file.
  const loaded = (logs !== null && logs.length > 0) || isReady;

  // A locally imported file wins, because the analyst chose it. Otherwise fall
  // back to the events the backend published, so the log views show the data
  // the analysis was actually built from rather than nothing.
  const safeLogs = (logs && logs.length > 0) ? logs : analysisEvents;

  const filteredBySearch = loaded && searchQuery
    ? safeLogs.filter(l => {
        const q = searchQuery.toLowerCase();
        return l.message?.toLowerCase().includes(q) ||
               l.rule?.toLowerCase().includes(q) ||
               l.sourceIP?.toLowerCase().includes(q) ||
               l.user?.toLowerCase().includes(q) ||
               l.host?.toLowerCase().includes(q);
      })
    : safeLogs;

  // Per-tab boundary, keyed on the tab, so a crash is contained to the view
  // that caused it and switching tabs recovers. Without this a single throw
  // blanked the entire dashboard.
  function renderContent() {
    return (
      <ErrorBoundary key={activeNav} label={NAV_LABELS[activeNav] || activeNav}>
        {renderTab()}
      </ErrorBoundary>
    );
  }

  function renderTab() {
    // Locked out is not the same as empty. Showing the import screen here sent
    // the analyst looking for a file when the server already had the answer
    // and was simply refusing the request.
    if (status === 'unauthorised') return <ApiKeyGate message={error} />;
    if (!loaded) return <ImportScreen onImport={handleImport} onSampleData={handleSampleData} />;

    switch (activeNav) {
      case 'logs':
        return (
          <div className="flex-1 flex flex-col p-4 min-h-0">
            <LiveLogs
              searchQuery={searchQuery}
              onSelectLog={handleSelectLog}
              onInvestigate={log => {
                handleSelectAlert(log);
                setActiveNav('alerts');
              }}
            />
          </div>
        );

      case 'email':
        return (
          <EmailAnalysis
            onSelectEmail={handleSelectEmail}
            onSearchLogs={q => { setSearchQuery(q); setActiveNav('logs'); }}
          />
        );

      case 'alerts':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <AISituationReport onSelectIncident={jumpToIncident} />
            <AnalysisCoverage />
            <AlertsPage
              logs={safeLogs}
              externalQuery={searchQuery}
              selectedAlert={selectedAlert}
              onSelect={a => { handleSelectAlert(a); setSearchQuery(''); }}
            />
          </div>
        );

      case 'ai':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* The live step feed belongs beside the reasoning it is producing.
                It was on the Alerts tab, so the steps appeared under the alert
                list while the tab named "AI Investigation" showed nothing. */}
            <QueueStatus onOpenQuestions={() => setActiveNav('response')} />
            <LiveAgentActivity />
            <AIInvestigation
              selectedId={focusedIncident}
              onSelect={setFocusedIncident}
            />
          </div>
        );

      case 'evidence':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <EvidenceGraph
              selectedId={focusedIncident}
              onSelect={setFocusedIncident}
            />
          </div>
        );

      case 'response':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <ResponsePage
              selectedId={focusedIncident}
              onSelect={setFocusedIncident}
            />
          </div>
        );

      case 'settings':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <IngestPanel onImport={handleImport} onSampleData={handleSampleData}
                         fileInfo={fileInfo} />
            <DetectionEngineering />
            <AuditLog />
            <Settings fileInfo={fileInfo}
                      onImport={() => document.querySelector('[data-import]')?.click()} />
          </div>
        );

      default:
        return null;
    }
  }

  return (
    <div className="h-screen flex flex-col bg-base overflow-hidden">
      {loading && <LoadingOverlay progress={loadProgress.done} total={loadProgress.total} />}
      <AnalysisProgress />
      {toast && <Toast message={toast.msg} type={toast.type} />}

      <Header
        logs={logs ?? []}
        fileInfo={fileInfo}
        onImport={handleImport}
        onSearch={handleSearch}
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen(p => !p)}
        theme={theme}
        onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
      />

      {/* States plainly whether the screen is showing a real analysis run or
          bundled demo data. Mock output must never read as real. */}
      <div className="flex items-center gap-2 px-4 py-1 border-b border-border bg-panel">
        <DataSourceBadge />
        {/* Both of these make a claim the reader will want to follow up, so
            both navigate to the view that answers it. */}
        <AnalysisCoverage compact onOpen={() => setActiveNav('alerts')} />
        <AnalystQuestions compact onOpen={() => setActiveNav('response')} />
      </div>

      <div className="flex flex-1 overflow-hidden">
        {(loaded || true) && (
          <Sidebar
            active={activeNav}
            onNav={id => { setActiveNav(id); setSearchQuery(''); }}
            collapsed={!sidebarOpen}
            logs={safeLogs}
            fileInfo={fileInfo}
          />
        )}

        <main className="flex-1 flex flex-col overflow-hidden bg-base">
          {renderContent()}
        </main>

        <AIPanel
          logs={safeLogs}
          activeNav={activeNav}
          selectedAlert={selectedAlert}
          focusedIncident={focusedIncident}
          onSelectIncident={jumpToIncident}
        />
      </div>

      <Footer logs={logs ?? []} />
    </div>
  );
}
