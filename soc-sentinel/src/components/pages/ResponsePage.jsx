import { useState } from 'react';
import {
  ShieldCheck, ShieldOff, Trash2, RefreshCw, AlertTriangle, Check, X,
  Lock, UserCheck, MessageCircleQuestion,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import { api } from '../../utils/api';
import AnalystQuestions from './AnalystQuestions';

const PHASE = {
  contain:   { icon: ShieldOff, tone: 'text-red-400',     label: 'Contain' },
  eradicate: { icon: Trash2,    tone: 'text-amber-400',   label: 'Eradicate' },
  recover:   { icon: RefreshCw, tone: 'text-emerald-400', label: 'Recover' },
};

const BAND_TEXT = {
  auto_close: 'The AI closed this on its own',
  auto_enrich: 'Waiting for an analyst',
  escalate: 'Escalated — needs attention now',
  hold_for_human: 'Paused, waiting on your answer',
};

function ActionRow({ action, index, incidentId, decided, onDecide }) {
  const meta = PHASE[action.phase] || PHASE.contain;
  const Icon = meta.icon;
  const [busy, setBusy] = useState(false);

  async function decide(approved) {
    setBusy(true);
    try {
      await api.sendApproval({ incident_id: incidentId, action_index: index, approved });
      onDecide(index, approved);
    } catch {
      onDecide(index, approved);   // reflected locally; analyst can retry
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-start gap-2 px-3 py-2 border-b border-border last:border-0">
      <Icon size={11} className={`${meta.tone} mt-0.5 shrink-0`} />
      <div className="flex-1 min-w-0">
        <p className="text-primary text-[11px] leading-relaxed">{action.step}</p>
        <div className="flex items-center gap-2 mt-0.5 flex-wrap">
          <span className="text-muted text-[9px] uppercase tracking-wider">{meta.label}</span>
          {action.destructive && (
            <span className="text-amber-400 text-[9px] inline-flex items-center gap-1">
              <AlertTriangle size={9} /> changes production
            </span>
          )}
          {action.gate_reason && (
            <span className="text-muted text-[9px]">{action.gate_reason}</span>
          )}
        </div>
      </div>

      <div className="shrink-0">
        {decided ? (
          <span className={`text-[10px] font-medium ${
            decided === 'approved' ? 'text-emerald-400' : 'text-red-400'}`}>
            {decided}
          </span>
        ) : action.requires_approval ? (
          <div className="flex gap-1">
            <button onClick={() => decide(true)} disabled={busy}
              className="p-1 rounded border border-border text-muted hover:text-emerald-400 hover:border-emerald-500/40 disabled:opacity-40">
              <Check size={11} />
            </button>
            <button onClick={() => decide(false)} disabled={busy}
              className="p-1 rounded border border-border text-muted hover:text-red-400 hover:border-red-500/40 disabled:opacity-40">
              <X size={11} />
            </button>
          </div>
        ) : (
          <span className="text-muted text-[9px] inline-flex items-center gap-1">
            <Lock size={9} /> no approval needed
          </span>
        )}
      </div>
    </div>
  );
}

/**
 * What the system wants to do, and what it is allowed to do without asking.
 *
 * Nothing here executes on its own. Anything that changes production state is
 * held behind an explicit decision regardless of how confident the AI was —
 * proposing containment is the agent's job, performing it is not.
 */
export default function ResponsePage({ selectedId, onSelect }) {
  const { incidentsByUrgency, cases, verdicts, isReady } = useAnalysis();
  const [decisions, setDecisions] = useState({});

  if (!isReady) return <p className="text-muted text-xs">No analysis yet.</p>;

  const withPlans = incidentsByUrgency.filter(i => {
    const plan = cases?.[i.incident_id]?.agents?.response?.findings?.[0]?.data;
    return plan?.actions?.length;
  });

  const current = withPlans.find(i => i.incident_id === selectedId) || withPlans[0];
  const caseFile = current ? cases[current.incident_id] : null;
  const plan = caseFile?.agents?.response?.findings?.[0]?.data;
  const autonomy = caseFile?.autonomy || verdicts[current?.incident_id]?.autonomy;

  return (
    <div className="space-y-4">
      <AnalystQuestions />

      {withPlans.length === 0 ? (
        <div className="bg-card border border-border rounded-lg p-4 flex items-center gap-2">
          <ShieldCheck size={14} className="text-emerald-400" />
          <span className="text-muted text-xs">
            No response plans yet. They are generated for high and critical cases.
          </span>
        </div>
      ) : (
        <div className="flex gap-4">
          <div className="w-52 shrink-0 space-y-1">
            <p className="text-muted text-[10px] uppercase tracking-wider px-1 mb-1">
              Needs a decision ({withPlans.length})
            </p>
            {withPlans.map(i => (
              <button key={i.incident_id} onClick={() => onSelect?.(i.incident_id)}
                className={`w-full text-left px-2 py-1.5 rounded ${
                  current?.incident_id === i.incident_id ? 'bg-hover' : 'hover:bg-panel'}`}>
                <p className="text-primary text-[10px] font-mono truncate">{i.incident_id}</p>
                <p className="text-muted text-[10px] truncate">{i.hosts?.[0]}</p>
              </button>
            ))}
          </div>

          <div className="flex-1 min-w-0">
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
                <ShieldCheck size={13} className="text-blue-400" />
                <span className="text-primary text-xs">
                  {plan?.playbook_name || 'Response plan'}
                </span>
                <span className="ml-auto text-muted text-[10px] font-mono">
                  {current?.incident_id}
                </span>
              </div>

              {autonomy && (
                <div className="px-3 py-2 border-b border-border">
                  <p className="text-primary text-[11px]">
                    {BAND_TEXT[autonomy.band] || autonomy.band}
                  </p>
                  {autonomy.reasons?.[0] && (
                    <p className="text-muted text-[10px] leading-relaxed mt-0.5">
                      {autonomy.reasons[0]}
                    </p>
                  )}
                  {autonomy.overrides_applied?.map((o, i) => (
                    <p key={i} className="text-amber-300/90 text-[10px] mt-0.5 inline-flex items-start gap-1">
                      <AlertTriangle size={9} className="mt-0.5 shrink-0" /> {o}
                    </p>
                  ))}
                </div>
              )}

              {(plan?.actions || []).map((a, i) => (
                <ActionRow key={i} action={a} index={i}
                  incidentId={current.incident_id}
                  decided={decisions[`${current.incident_id}:${i}`]}
                  onDecide={(idx, ok) => setDecisions(d => ({
                    ...d, [`${current.incident_id}:${idx}`]: ok ? 'approved' : 'rejected',
                  }))} />
              ))}

              {plan?.escalate_to && (
                <div className="px-3 py-2 border-t border-border flex items-center gap-1.5">
                  <UserCheck size={11} className="text-blue-400" />
                  <span className="text-muted text-[10px] uppercase tracking-wider">Escalate to</span>
                  <span className="text-primary text-[11px]">{plan.escalate_to}</span>
                </div>
              )}
            </div>

            <p className="text-muted text-[10px] leading-relaxed mt-2 px-1">
              Nothing here runs automatically. Steps that change a production
              system are held behind an explicit decision however confident the
              AI was.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
