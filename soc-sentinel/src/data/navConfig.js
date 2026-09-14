import { Activity, AlertTriangle, Brain, Network, ShieldCheck, Mail, Settings, UserCheck, Target } from 'lucide-react';

/**
 * Five tabs, following what actually happens to a log.
 *
 *   logs arrive -> something looks wrong -> the AI investigates ->
 *   here is what connects -> here is what to do about it
 *
 * The previous fifteen tabs mirrored how the system is built rather than how
 * an analyst works, so finding anything meant knowing the architecture. The
 * capabilities did not go away — they moved to the step of the flow where
 * someone would actually look for them.
 */
export const NAV_ITEMS = [
  { id: 'logs',        icon: Activity,      label: 'Live Logs' },
  { id: 'alerts',      icon: AlertTriangle, label: 'Alerts', badge: true },
  { id: 'ai',          icon: Brain,         label: 'AI Investigation' },
  // Logs a person chose to send to the AI themselves, kept apart from the
  // queue the funnel decides on — the whole point is that a human picked it.
  { id: 'manual',      icon: UserCheck,     label: 'Sent by Analyst' },
  // Whether any of the above was right. Kept as its own tab because every
  // other tab reports what happened, and this reports how well it went.
  { id: 'scorecard',   icon: Target,        label: 'Accuracy' },
  { id: 'evidence',    icon: Network,       label: 'Evidence Graph' },
  { id: 'response',    icon: ShieldCheck,   label: 'Response' },
  { id: 'email',       icon: Mail,          label: 'Phishing' },
  { id: 'settings',    icon: Settings,      label: 'Settings' },
];

export const NAV_LABELS = Object.fromEntries(NAV_ITEMS.map(t => [t.id, t.label]));
