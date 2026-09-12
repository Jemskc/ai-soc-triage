import { X, Shield, Globe, User, Monitor, Hash, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { useState } from 'react';
import { severityBg, severityColor } from '../../utils/severityUtils';
import { getMitreTechnique } from '../../utils/mitreMapper';
import AITriageVerdict from './AITriageVerdict';
import RiskBreakdown from '../agents/RiskBreakdown';
import AgentFindings from '../agents/AgentFindings';
import InvestigationTrace from '../investigation/InvestigationTrace';
import ResponseActions from '../agents/ResponseActions';
import { useAnalysis } from '../../context/AnalysisContext';

export default function AlertDetail({ alert, onClose }) {
  const [rawExpanded, setRawExpanded] = useState(false);
  const { verdictFor, knowledgeFor, verdicts, caseFor } = useAnalysis();
  if (!alert) return null;

  // An alert row may be an incident from the analysis bundle, or a legacy
  // client-side alert. Only the former carries an AI verdict.
  const incidentId = alert.incident_id || alert.id;
  const aiVerdict = verdictFor(incidentId);
  const knowledge = knowledgeFor(incidentId);
  const ungrounded = verdicts[incidentId]?.ungrounded_techniques ?? [];

  // Multi-agent output, when the run used the orchestrator.
  const risk = verdicts[incidentId]?.risk ?? null;
  const caseFile = caseFor(incidentId);
  const investigation = caseFile?.investigation ?? verdicts[incidentId]?.investigation ?? null;
  const autonomyDecision = caseFile?.autonomy ?? verdicts[incidentId]?.autonomy ?? null;
  const responsePlan =
    caseFile?.agents?.response?.findings?.[0]?.data ?? null;

  // Prefer the grounded technique from the AI over the keyword mapper, which
  // covers 11 techniques and defaults everything else to T1190.
  const mitre =
    aiVerdict?.mitre_technique ||
    alert.mitre ||
    getMitreTechnique(alert.rule, alert.message).technique;

  const fields = [
    { icon: Hash, label: 'Alert ID', value: alert.id },
    { icon: Clock, label: 'Timestamp', value: new Date(alert.timestamp).toLocaleString() },
    { icon: Shield, label: 'Rule', value: alert.rule },
    { icon: Globe, label: 'Source IP', value: alert.sourceIP },
    { icon: Globe, label: 'Dest IP', value: alert.destIP },
    { icon: User, label: 'User', value: alert.user },
    { icon: Monitor, label: 'Host', value: alert.host },
    { icon: Hash, label: 'MITRE', value: mitre },
    { icon: Hash, label: 'Source', value: alert.source },
    { icon: Hash, label: 'Status', value: alert.status },
  ];

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden animate-fadeIn">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${severityBg(alert.severity)}`}>
            {alert.severity}
          </span>
          <span className="text-primary text-sm font-medium">{alert.id}</span>
        </div>
        <button onClick={onClose} className="text-muted hover:text-primary transition-colors">
          <X size={16} />
        </button>
      </div>

      <div className="p-4 space-y-4">
        <p className="text-primary text-xs leading-relaxed border-l-2 pl-3" style={{ borderColor: severityColor(alert.severity) }}>
          {alert.message}
        </p>

        {/* The AI verdict leads, because it is the answer the analyst opened
            this panel for. The raw fields below are the corroboration. */}
        {/* Fused risk first — it is the decision. The triage verdict below is
            the reasoning behind the largest single factor in it. */}
        <RiskBreakdown risk={risk} />

        <AITriageVerdict
          incidentId={incidentId}
          verdict={aiVerdict}
          knowledge={knowledge}
          ungrounded={ungrounded}
        />

        {/* The investigation trace is the evidence for the verdict above it:
            every question the agent asked and what came back. */}
        {investigation && (
          <InvestigationTrace
            investigation={investigation}
            autonomy={autonomyDecision}
          />
        )}

        {caseFile?.agents && Object.keys(caseFile.agents).length > 0 && (
          <AgentFindings agents={caseFile.agents} />
        )}

        {responsePlan && (
          <ResponseActions incidentId={incidentId} plan={responsePlan} />
        )}

        <div className="grid grid-cols-2 gap-2">
          {fields.map(({ icon: Icon, label, value }) => (
            <div key={label} className="bg-panel rounded p-2">
              <div className="flex items-center gap-1.5 mb-0.5">
                <Icon size={10} className="text-muted shrink-0" />
                <span className="text-muted text-[10px] uppercase tracking-wider">{label}</span>
              </div>
              <span className="text-primary text-xs font-mono truncate block">{value || '—'}</span>
            </div>
          ))}
        </div>

        <div className="border border-border rounded overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-3 py-2 bg-panel text-muted text-xs hover:text-primary transition-colors"
            onClick={() => setRawExpanded(p => !p)}
          >
            <span>Raw Log Entry</span>
            {rawExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
          {rawExpanded && (
            <pre className="text-[10px] text-primary bg-base p-3 overflow-auto max-h-48 font-mono">
              {JSON.stringify(alert._raw || alert, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
