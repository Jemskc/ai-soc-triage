import { LayoutDashboard, AlertTriangle, Search, Crosshair, Monitor, FileText, BookOpen, Settings, Database, Terminal, Mail } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'overview',       icon: LayoutDashboard, label: 'Overview' },
  { id: 'alerts',         icon: AlertTriangle,   label: 'Alerts',          badge: true },
  { id: 'logs',           icon: Terminal,         label: 'Logs' },
  { id: 'investigations', icon: Search,           label: 'Investigations' },
  { id: 'hunting',        icon: Crosshair,        label: 'Threat Hunting' },
  { id: 'email',          icon: Mail,             label: 'Email Analysis' },
  { id: 'assets',         icon: Monitor,          label: 'Assets' },
  { id: 'reports',        icon: FileText,         label: 'Reports' },
  { id: 'playbooks',      icon: BookOpen,         label: 'Playbooks' },
  { id: 'settings',       icon: Settings,         label: 'Settings' },
];

export default function Sidebar({ active, onNav, collapsed, logs, fileInfo }) {
  const criticalCount = logs ? logs.filter(l => l.severity === 'CRITICAL').length : 0;
  const loaded = fileInfo !== null;

  return (
    <aside className={`shrink-0 border-r border-border bg-panel flex flex-col transition-all duration-200 ${collapsed ? 'w-12' : 'w-[220px]'}`}>
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.map(({ id, icon: Icon, label, badge }) => {
          const isActive = active === id;
          return (
            <button
              key={id}
              onClick={() => onNav(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 text-xs transition-colors relative ${
                isActive
                  ? 'bg-hover text-primary border-r-2 border-blue-500'
                  : 'text-muted hover:text-primary hover:bg-hover/50'
              }`}
              title={collapsed ? label : undefined}
            >
              <Icon size={14} className="shrink-0" />
              {!collapsed && <span className="flex-1 text-left">{label}</span>}
              {!collapsed && badge && criticalCount > 0 && (
                <span className="bg-red-500 text-white text-[9px] font-bold rounded-full min-w-[16px] h-4 flex items-center justify-center px-1">
                  {criticalCount > 99 ? '99+' : criticalCount}
                </span>
              )}
              {collapsed && badge && criticalCount > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
              )}
            </button>
          );
        })}
      </nav>

      {!collapsed && (
        <div className="p-3 border-t border-border">
          <p className="text-muted text-[10px] uppercase tracking-wider mb-2">Data Sources</p>
          {loaded ? (
            <div className="bg-hover rounded p-2 space-y-1">
              <div className="flex items-center gap-2">
                <Database size={10} className="text-green-400 shrink-0" />
                <span className="text-primary text-[10px] truncate font-mono">{fileInfo.name}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-green-400">● Active</span>
                <span className="text-[10px] text-muted">{logs?.length?.toLocaleString()} events</span>
              </div>
            </div>
          ) : (
            <p className="text-muted text-[10px]">No sources connected</p>
          )}
        </div>
      )}
    </aside>
  );
}
