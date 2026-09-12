import { Crosshair, Play, ExternalLink } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

function attackUrl(technique) {
  const id = String(technique || '').match(/T\d{4}(?:\.\d{3})?/)?.[0];
  return id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` : null;
}

/**
 * Hunting hypotheses generated from this data, grounded in ATT&CK detection
 * guidance.
 *
 * The tab previously showed four top-N tables, which tells you what is frequent
 * rather than what is worth chasing. A hypothesis states what might be true,
 * why, and the query that would confirm it.
 */
export default function AIHuntHypotheses({ onRunQuery }) {
  const { campaign, isReady } = useAnalysis();
  const analysis = campaign?.hunting?.payload;
  const hypotheses = Array.isArray(analysis?.hypotheses) ? analysis.hypotheses : [];

  if (!isReady || hypotheses.length === 0) return null;

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-panel">
        <Crosshair size={14} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          AI Hunting Hypotheses
        </span>
        <span className="ml-auto text-muted text-[10px]">
          grounded in ATT&amp;CK detection guidance
        </span>
      </div>

      <div className="divide-y divide-border">
        {hypotheses.map((h, i) => {
          const href = attackUrl(h.technique);
          return (
            <div key={i} className="p-3 space-y-2">
              <div className="flex items-start gap-2">
                <span className="text-muted font-mono text-[11px] mt-0.5 shrink-0">{i + 1}.</span>
                <p className="text-primary text-xs leading-relaxed flex-1">{h.hypothesis}</p>
              </div>

              {h.rationale && (
                <p className="text-muted text-[11px] leading-relaxed pl-6">{h.rationale}</p>
              )}

              <div className="flex items-center gap-2 pl-6 flex-wrap">
                {h.query && (
                  <button
                    onClick={() => onRunQuery?.(h.query)}
                    className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-panel hover:bg-hover border border-border text-primary text-[11px] font-mono transition-colors"
                  >
                    <Play size={10} className="text-blue-400" />
                    {h.query}
                  </button>
                )}
                {href && (
                  <a
                    href={href}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 text-[10px] font-mono"
                  >
                    {h.technique}
                    <ExternalLink size={9} />
                  </a>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
