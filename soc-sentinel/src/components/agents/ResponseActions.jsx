import { useState } from 'react';
import { ShieldOff, AlertTriangle, Check, X, Lock } from 'lucide-react';
import { api } from '../../utils/api';

const PHASE_TONE = {
  contain: 'text-red-400',
  eradicate: 'text-amber-400',
  recover: 'text-emerald-400',
};

/**
 * Proposed response actions, held behind an explicit human decision.
 *
 * Nothing here executes. Destructive steps are marked and cannot be actioned
 * without an analyst approving them individually — an agent that can isolate a
 * domain controller on its own judgement is a liability, not a feature.
 */
export default function ResponseActions({ incidentId, plan }) {
  const [decisions, setDecisions] = useState({});
  if (!plan?.actions?.length) return null;

  async function decide(index, approved) {
    setDecisions(d => ({ ...d, [index]: approved ? 'approved' : 'rejected' }));
    try {
      await api.sendApproval({ incident_id: incidentId, action_index: index, approved });
    } catch {
      // The decision stays reflected in the UI; the analyst can retry.
    }
  }

  const needingApproval = plan.actions.filter(a => a.requires_approval).length;

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
        <ShieldOff size={13} className="text-blue-400" />
        <span className="text-muted text-[10px] uppercase tracking-wider">
          {plan.playbook_name || 'Response Plan'}
        </span>
        <span className="ml-auto text-muted text-[10px]">
          {needingApproval} of {plan.actions.length} need approval
        </span>
      </div>

      <div className="divide-y divide-border">
        {plan.actions.map((a, i) => {
          const decision = decisions[i];
          return (
            <div key={i} className="p-2.5 flex items-start gap-2">
              <span className={`text-[9px] uppercase tracking-wider font-semibold shrink-0 mt-0.5 w-14 ${PHASE_TONE[a.phase] || 'text-muted'}`}>
                {a.phase}
              </span>

              <div className="flex-1 min-w-0">
                <p className="text-primary text-[11px] leading-relaxed">{a.step}</p>
                {a.destructive && (
                  <span className="inline-flex items-center gap-1 mt-1 text-amber-400 text-[9px]">
                    <AlertTriangle size={9} />
                    Changes production state
                  </span>
                )}
              </div>

              <div className="shrink-0">
                {decision ? (
                  <span className={`text-[10px] font-medium ${
                    decision === 'approved' ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {decision}
                  </span>
                ) : a.requires_approval ? (
                  <div className="flex gap-1">
                    <button onClick={() => decide(i, true)}
                      className="p-1 rounded border border-border text-muted hover:text-emerald-400 hover:border-emerald-500/40 transition-colors">
                      <Check size={11} />
                    </button>
                    <button onClick={() => decide(i, false)}
                      className="p-1 rounded border border-border text-muted hover:text-red-400 hover:border-red-500/40 transition-colors">
                      <X size={11} />
                    </button>
                  </div>
                ) : (
                  <span className="inline-flex items-center gap-1 text-muted text-[9px]">
                    <Lock size={9} /> no approval needed
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {plan.escalate_to && (
        <p className="px-3 py-2 border-t border-border text-[10px] text-muted">
          Escalate to: <span className="text-primary">{plan.escalate_to}</span>
        </p>
      )}
    </div>
  );
}
