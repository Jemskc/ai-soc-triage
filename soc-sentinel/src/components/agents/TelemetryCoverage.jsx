import { Radar, Check, X } from 'lucide-react';

const DOMAIN_LABELS = {
  endpoint: 'Endpoint', identity: 'Identity', network: 'Network',
  email: 'Email', dns: 'DNS', cloud: 'Cloud',
  firewall: 'Firewall', saas: 'SaaS', ad: 'Active Directory',
};

/**
 * Which telemetry domains are actually wired up.
 *
 * Shown prominently because an unconnected domain is a blind spot, and a
 * verdict is only as complete as the evidence available to it. "We found
 * nothing in Cloud" and "we cannot see Cloud" are different statements.
 */
export default function TelemetryCoverage({ coverage, compact = false }) {
  if (!coverage) return null;
  const { connected = [], not_connected = [], coverage_ratio, sources = {} } = coverage;

  if (compact) {
    return (
      <span className="text-[10px] text-muted">
        {connected.length}/{connected.length + not_connected.length} domains connected
      </span>
    );
  }

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <Radar size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          Telemetry Coverage
        </span>
        <span className="ml-auto text-primary text-[11px] font-mono">
          {Math.round((coverage_ratio || 0) * 100)}%
        </span>
      </div>

      <div className="p-3 grid grid-cols-2 gap-x-4 gap-y-1.5">
        {connected.map(d => (
          <div key={d} className="flex items-start gap-1.5">
            <Check size={11} className="text-emerald-400 mt-0.5 shrink-0" />
            <div className="min-w-0">
              <p className="text-primary text-[11px]">{DOMAIN_LABELS[d] || d}</p>
              {sources[d] && (
                <p className="text-muted text-[9px] leading-tight truncate">{sources[d]}</p>
              )}
            </div>
          </div>
        ))}
        {not_connected.map(d => (
          <div key={d} className="flex items-start gap-1.5 opacity-60">
            <X size={11} className="text-muted mt-0.5 shrink-0" />
            <div className="min-w-0">
              <p className="text-muted text-[11px]">{DOMAIN_LABELS[d] || d}</p>
              <p className="text-muted/70 text-[9px] leading-tight">no connector</p>
            </div>
          </div>
        ))}
      </div>

      {not_connected.length > 0 && (
        <p className="px-3 pb-3 text-muted text-[10px] leading-relaxed">
          Blind spots limit corroboration. Verdicts on these cases are bounded by
          what the connected domains can see.
        </p>
      )}
    </div>
  );
}
