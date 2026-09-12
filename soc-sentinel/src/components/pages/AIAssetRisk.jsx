import { Monitor, User, ShieldAlert } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

function riskTone(score) {
  if (score >= 8) return { bar: 'bg-red-500', text: 'text-red-400' };
  if (score >= 5) return { bar: 'bg-amber-500', text: 'text-amber-400' };
  return { bar: 'bg-emerald-500', text: 'text-emerald-400' };
}

/**
 * Assets ranked by AI-assessed risk, with the reason attached.
 *
 * The previous Assets view counted events per host, which ranks the noisiest
 * machine first rather than the most compromised one. Risk here comes from what
 * the incidents touching that asset actually mean.
 */
export default function AIAssetRisk({ onSelectIncident }) {
  const { campaign, isReady } = useAnalysis();
  const analysis = campaign?.assets?.payload;
  const assets = Array.isArray(analysis?.assets) ? analysis.assets : [];

  if (!isReady || assets.length === 0) return null;

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
        <ShieldAlert size={14} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          AI Risk Assessment
        </span>
        <span className="ml-auto text-muted text-[10px]">
          {assets.length} asset{assets.length === 1 ? '' : 's'} at risk
        </span>
      </div>

      <div className="divide-y divide-border">
        {assets.map((asset, i) => {
          const score = Number.isFinite(asset.risk_score) ? asset.risk_score : 0;
          const tone = riskTone(score);
          const Icon = asset.kind === 'user' ? User : Monitor;

          return (
            <div key={`${asset.name}-${i}`} className="p-3 space-y-2">
              <div className="flex items-center gap-2">
                <Icon size={12} className="text-muted shrink-0" />
                <span className="text-primary text-xs font-mono truncate">{asset.name}</span>
                <span className="text-muted text-[10px] uppercase">{asset.kind}</span>
                <span className={`ml-auto font-mono text-xs tabular-nums ${tone.text}`}>
                  {score}/10
                </span>
              </div>

              <div className="h-1 bg-hover rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${tone.bar}`} style={{ width: `${score * 10}%` }} />
              </div>

              {asset.reason && (
                <p className="text-muted text-[11px] leading-relaxed">{asset.reason}</p>
              )}

              {Array.isArray(asset.incident_ids) && asset.incident_ids.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {asset.incident_ids.slice(0, 5).map(id => (
                    <button
                      key={id}
                      onClick={() => onSelectIncident?.(id)}
                      className="px-1.5 py-0.5 rounded bg-panel hover:bg-hover text-muted hover:text-primary text-[10px] font-mono transition-colors"
                    >
                      {id}
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
