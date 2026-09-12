import { useState, useCallback, useEffect } from 'react';
import { parseLogFile, loadMockData } from './utils/logParser';
import { MOCK_LOGS } from './data/mockData';

import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Footer from './components/Footer';
import AIPanel from './components/AIPanel';
import ImportScreen from './components/ImportScreen';
import LogsExplorer from './pages/LogsExplorer';
import EmailAnalysis from './pages/EmailAnalysis';

import KPICard from './components/overview/KPICard';
import ThreatTrendChart from './components/overview/ThreatTrendChart';
import SeverityDonut from './components/overview/SeverityDonut';
import TopSourcesTable from './components/overview/TopSourcesTable';
import RecentAlertsTable from './components/overview/RecentAlertsTable';

import AlertsPage from './components/alerts/AlertsPage';
import InvestigationTimeline from './components/investigations/InvestigationTimeline';
import ThreatHunting from './components/pages/ThreatHunting';
import Assets from './components/pages/Assets';
import Reports from './components/pages/Reports';
import Settings from './components/pages/Settings';

import { AlertTriangle, Shield, Globe, Users, Loader } from 'lucide-react';

import { AnalysisProvider, useAnalysis } from './context/AnalysisContext';
import AnalysisProgress, { DataSourceBadge } from './components/AnalysisProgress';
import AISituationReport from './components/overview/AISituationReport';
import AnalysisCoverage from './components/AnalysisCoverage';
import LiveAgentActivity from './components/LiveAgentActivity';
import AIAttackChain from './components/investigations/AIAttackChain';
import AIAssetRisk from './components/pages/AIAssetRisk';
import AIHuntHypotheses from './components/pages/AIHuntHypotheses';
import BenchmarkReport from './components/pages/BenchmarkReport';
import Playbooks from './components/pages/Playbooks';
import SOCCore from './components/agents/SOCCore';
import AuditLog from './components/pages/AuditLog';
import AnalystQuestions from './components/pages/AnalystQuestions';
import DetectionEngineering from './components/pages/DetectionEngineering';
import IngestPanel from './components/pages/IngestPanel';

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
  const { incidentsByUrgency, isReady, events: analysisEvents, metrics } = useAnalysis();
  const [logs, setLogs] = useState(null);
  const [fileInfo, setFileInfo] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [activeNav, setActiveNav] = useState('overview');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [loading, setLoading] = useState(false);
  const [loadProgress, setLoadProgress] = useState({ done: 0, total: 0 });
  const [toast, setToast] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
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
      setActiveNav('overview');
      showToast(`${parsed.length.toLocaleString()} records loaded from ${file.name}`, 'success');
    } catch (err) {
      showToast('Could not parse file. Try JSON, CSV, or plain text log format.');
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
    setActiveNav('overview');
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

  function renderContent() {
    if (activeNav === 'email') {
      return (
        <EmailAnalysis
          onSelectEmail={handleSelectEmail}
          onSearchLogs={query => { setSearchQuery(query); setActiveNav('logs'); }}
        />
      );
    }
    if (!loaded) return <ImportScreen onImport={handleImport} onSampleData={handleSampleData} />;


    switch (activeNav) {
      case 'overview':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4 animate-fadeIn">
            {/* What is happening, before how many of it there are. */}
            <LiveAgentActivity />
            <AISituationReport onSelectIncident={jumpToIncident} />
            {/* Answers "did the AI actually check this?" before anything else
                on the page invites the reader to assume it did. */}
            <AnalysisCoverage />
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <KPICard
                label="Total Events"
                value={metrics?.events_ingested ?? safeLogs.length}
                icon={Shield}
                color="#3b82f6"
                sub={metrics ? `${safeLogs.length.toLocaleString()} published to views` : 'from imported file'}
              />
              <KPICard
                label={metrics ? 'Incidents' : 'Critical Alerts'}
                value={metrics?.incidents ?? safeLogs.filter(l => l.severity === 'CRITICAL').length}
                icon={AlertTriangle}
                color="#ef4444"
                sub={metrics ? `${metrics.rule_alerts} rule alerts correlated` : 'immediate action required'}
              />
              <KPICard label="Unique Source IPs" value={new Set(safeLogs.map(l => l.sourceIP)).size} icon={Globe} color="#f97316" sub="distinct attacker addresses" />
              <KPICard label="Unique Users" value={new Set(safeLogs.map(l => l.user).filter(u => u !== 'Unknown')).size} icon={Users} color="#a855f7" sub="affected accounts" />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2">
                <ThreatTrendChart logs={safeLogs} />
              </div>
              <SeverityDonut logs={safeLogs} />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <TopSourcesTable logs={safeLogs} />
              <RecentAlertsTable logs={safeLogs} onSelect={alert => { handleSelectAlert(alert); setActiveNav('alerts'); }} />
            </div>
          </div>
        );

      case 'alerts':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <AlertsPage
              logs={safeLogs}
              externalQuery={searchQuery}
              selectedAlert={selectedAlert}
              onSelect={a => { handleSelectAlert(a); setSearchQuery(''); }}
            />
          </div>
        );

      case 'logs':
        return (
          <LogsExplorer
            logs={safeLogs}
            onSelectLog={handleSelectLog}
            onInvestigate={log => { handleSelectAlert(log); setActiveNav('investigations'); }}
          />
        );


      case 'investigations':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <AIAttackChain onSelectIncident={jumpToIncident} />
            <InvestigationTimeline logs={safeLogs} selectedAlert={selectedAlert} />
          </div>
        );

      case 'hunting':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <AIHuntHypotheses onRunQuery={q => { setSearchQuery(q); setActiveNav('logs'); }} />
            <ThreatHunting logs={safeLogs} />
          </div>
        );

      case 'assets':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <AIAssetRisk onSelectIncident={jumpToIncident} />
            <Assets logs={safeLogs} />
          </div>
        );

      case 'reports':
        return (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <BenchmarkReport />
            <Reports logs={safeLogs} fileInfo={fileInfo} />
          </div>
        );

      case 'soccore':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <SOCCore onSelectIncident={jumpToIncident} />
          </div>
        );

      case 'playbooks':
        return <div className="flex-1 overflow-y-auto p-4"><Playbooks /></div>;

      case 'detection':
        return <div className="flex-1 overflow-y-auto p-4"><DetectionEngineering /></div>;

      case 'questions':
        return <div className="flex-1 overflow-y-auto p-4"><AnalystQuestions /></div>;

      case 'audit':
        return <div className="flex-1 overflow-y-auto p-4"><AuditLog /></div>;

      case 'ingest':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <IngestPanel
              onImport={handleImport}
              onSampleData={handleSampleData}
              fileInfo={fileInfo}
            />
          </div>
        );

      case 'settings':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <Settings fileInfo={fileInfo} onImport={() => document.querySelector('[data-import]')?.click()} />
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
        <AnalystQuestions compact />
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
        />
      </div>

      <Footer logs={logs ?? []} />
    </div>
  );
}
