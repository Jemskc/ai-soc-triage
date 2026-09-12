import {
  LayoutDashboard, AlertTriangle, Search, Crosshair,
  Monitor, FileText, BookOpen, Settings, Terminal, Mail, Bot, Upload, FileSearch, MessageCircleQuestion,
} from 'lucide-react';

export const NAV_ITEMS = [
  { id: 'overview',       icon: LayoutDashboard, label: 'Overview' },
  { id: 'soccore',        icon: Bot,             label: 'AI SOC Core' },
  { id: 'alerts',         icon: AlertTriangle,   label: 'Alerts',         badge: true },
  { id: 'logs',           icon: Terminal,        label: 'Logs Explorer' },
  { id: 'investigations', icon: Search,          label: 'Investigations' },
  { id: 'hunting',        icon: Crosshair,       label: 'Threat Hunting' },
  { id: 'email',          icon: Mail,            label: 'Email Analysis' },
  { id: 'assets',         icon: Monitor,         label: 'Assets' },
  { id: 'reports',        icon: FileText,        label: 'Reports' },
  { id: 'playbooks',      icon: BookOpen,        label: 'Playbooks' },
  { id: 'ingest',         icon: Upload,          label: 'Ingest Logs' },
  { id: 'questions',      icon: MessageCircleQuestion, label: 'Agent Questions' },
  { id: 'audit',          icon: FileSearch,      label: 'Audit Trail' },
  { id: 'settings',       icon: Settings,        label: 'Settings' },
];

// Derive tab labels map automatically — never manually maintained
export const NAV_LABELS = Object.fromEntries(NAV_ITEMS.map(t => [t.id, t.label]));
