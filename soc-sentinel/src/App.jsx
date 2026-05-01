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

  const loaded = logs !== null && logs.length > 0;

  const filteredBySearch = loaded && searchQuery
    ? logs.filter(l => {
        const q = searchQuery.toLowerCase();
        return l.message?.toLowerCase().includes(q) ||
               l.rule?.toLowerCase().includes(q) ||
               l.sourceIP?.toLowerCase().includes(q) ||
               l.user?.toLowerCase().includes(q) ||
               l.host?.toLowerCase().includes(q);
      })
    : logs;

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
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <KPICard label="Total Events" value={logs.length} icon={Shield} color="#3b82f6" sub="from imported file" />
              <KPICard label="Critical Alerts" value={logs.filter(l => l.severity === 'CRITICAL').length} icon={AlertTriangle} color="#ef4444" sub="immediate action required" />
              <KPICard label="Unique Source IPs" value={new Set(logs.map(l => l.sourceIP)).size} icon={Globe} color="#f97316" sub="distinct attacker addresses" />
              <KPICard label="Unique Users" value={new Set(logs.map(l => l.user).filter(u => u !== 'Unknown')).size} icon={Users} color="#a855f7" sub="affected accounts" />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2">
                <ThreatTrendChart logs={logs} />
              </div>
              <SeverityDonut logs={logs} />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <TopSourcesTable logs={logs} />
              <RecentAlertsTable logs={logs} onSelect={alert => { handleSelectAlert(alert); setActiveNav('alerts'); }} />
            </div>
          </div>
        );

      case 'alerts':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <AlertsPage
              logs={searchQuery ? (filteredBySearch ?? []) : logs}
              selectedAlert={selectedAlert}
              onSelect={a => { handleSelectAlert(a); setSearchQuery(''); }}
            />
          </div>
        );

      case 'logs':
        return (
          <LogsExplorer
            logs={logs}
            onSelectLog={handleSelectLog}
            onInvestigate={log => { handleSelectAlert(log); setActiveNav('investigations'); }}
          />
        );


      case 'investigations':
        return (
          <div className="flex-1 overflow-y-auto p-4">
            <InvestigationTimeline logs={logs} selectedAlert={selectedAlert} />
          </div>
        );

      case 'hunting':
        return <div className="flex-1 overflow-y-auto p-4"><ThreatHunting logs={logs} /></div>;

      case 'assets':
        return <div className="flex-1 overflow-y-auto p-4"><Assets logs={logs} /></div>;

      case 'reports':
        return <div className="flex-1 overflow-y-auto p-4"><Reports logs={logs} fileInfo={fileInfo} /></div>;

      case 'playbooks':
        return (
          <div className="flex-1 flex items-center justify-center text-muted animate-fadeIn">
            <div className="text-center space-y-2">
              <p className="text-primary font-medium">Playbooks</p>
              <p className="text-xs">Automated response playbooks coming soon.</p>
            </div>
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

      <div className="flex flex-1 overflow-hidden">
        {(loaded || true) && (
          <Sidebar
            active={activeNav}
            onNav={id => { setActiveNav(id); setSearchQuery(''); }}
            collapsed={!sidebarOpen}
            logs={logs}
            fileInfo={fileInfo}
          />
        )}

        <main className="flex-1 flex flex-col overflow-hidden bg-base">
          {renderContent()}
        </main>

        <AIPanel
          logs={logs}
          selectedAlert={selectedAlert}
          selectedLog={selectedLog}
          selectedEmail={selectedEmail}
        />
      </div>

      <Footer logs={logs ?? []} />
    </div>
  );
}
