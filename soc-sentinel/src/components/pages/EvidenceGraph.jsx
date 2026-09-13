import { useEffect, useMemo, useState } from 'react';
import {
  Network, Monitor, User, Cpu, Globe, Hash, FileWarning, Shield, Server,
  ChevronDown,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import { api } from '../../utils/api';

const KIND = {
  alert:     { icon: FileWarning, tone: 'text-red-400',     label: 'Incident' },
  host:      { icon: Monitor,     tone: 'text-blue-400',    label: 'Host' },
  user:      { icon: User,        tone: 'text-purple-400',  label: 'Account' },
  process:   { icon: Cpu,         tone: 'text-amber-400',   label: 'Process' },
  ip:        { icon: Globe,       tone: 'text-cyan-400',    label: 'Address' },
  technique: { icon: Shield,      tone: 'text-emerald-400', label: 'Technique' },
  event:     { icon: Hash,        tone: 'text-slate-400',   label: 'Event ID' },
  rule:      { icon: Server,      tone: 'text-indigo-400',  label: 'Detection' },
};

const short = (p) => String(p || '').split('\\').pop();

/**
 * Everything one incident touches, and how the pieces connect.
 *
 * Built from the correlated incident plus whatever the agent's investigation
 * turned up, rather than from a fixed schema — the point is to show the links
 * the system actually found, including the ones that cross machines and
 * accounts, which is where an intrusion becomes visible.
 */
function buildGraph(incident, caseFile) {
  const nodes = [];
  const seen = new Set();
  const add = (kind, value, detail) => {
    const id = `${kind}:${value}`;
    if (!value || seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, kind, value, detail });
  };

  const v = caseFile?.investigation?.verdict || {};

  (incident.hosts || []).forEach(h =>
    add('host', h, caseFile?.asset_criticality
      ? `criticality: ${caseFile.asset_criticality}` : ''));
  (incident.users || []).forEach(u => add('user', u, ''));
  (incident.processes || []).forEach(p => add('process', short(p), p));
  (incident.event_ids || []).forEach(e => add('event', e, ''));
  (incident.rules_fired || []).forEach(r => add('rule', r.rule, `${r.count} firing(s)`));
  (incident.techniques_suspected || []).forEach(t =>
    add('technique', t.technique, 'suspected by correlation'));

  if (v.mitre_technique && !String(v.mitre_technique).startsWith('UNKNOWN')) {
    add('technique', v.mitre_technique, 'attributed by the AI');
  }
  (incident.sample_alerts || []).forEach(a => {
    if (a.source_ip && !['-', '', '127.0.0.1', '::1'].includes(a.source_ip)) {
      add('ip', a.source_ip, '');
    }
  });

  return nodes;
}

function Branch({ nodes, kind, last }) {
  const meta = KIND[kind];
  const items = nodes.filter(n => n.kind === kind);
  if (!items.length) return null;
  const Icon = meta.icon;

  return (
    <div className="relative pl-5">
      <span className="absolute left-0 top-2 text-muted select-none font-mono text-[11px]">
        {last ? '└──' : '├──'}
      </span>
      <div className="py-1">
        <div className="flex items-center gap-1.5">
          <Icon size={11} className={meta.tone} />
          <span className="text-muted text-[10px] uppercase tracking-wider">
            {meta.label} ({items.length})
          </span>
        </div>
        <div className="pl-4 mt-0.5 space-y-0.5">
          {items.slice(0, 8).map(n => (
            <div key={n.id} className="flex items-baseline gap-2">
              <span className="text-primary text-[11px] font-mono break-all">{n.value}</span>
              {n.detail && (
                <span className="text-muted text-[10px]">{n.detail}</span>
              )}
            </div>
          ))}
          {items.length > 8 && (
            <span className="text-muted text-[10px]">+{items.length - 8} more</span>
          )}
        </div>
      </div>
    </div>
  );
}

export default function EvidenceGraph({ selectedId, onSelect }) {
  const { incidentsByUrgency, cases, verdicts, isReady } = useAnalysis();
  const [showShared, setShowShared] = useState(true);

  const current = useMemo(() => {
    if (!incidentsByUrgency.length) return null;
    return incidentsByUrgency.find(i => i.incident_id === selectedId) || incidentsByUrgency[0];
  }, [incidentsByUrgency, selectedId]);

  // Entities that appear in more than one incident. This is the signal that a
  // set of separate alerts is actually one intrusion moving through the estate.
  const shared = useMemo(() => {
    const counts = new Map();
    incidentsByUrgency.forEach(inc => {
      [...(inc.hosts || []).map(h => ['host', h]),
       ...(inc.users || []).map(u => ['user', u])].forEach(([k, v]) => {
        const key = `${k}:${v}`;
        const entry = counts.get(key) || { kind: k, value: v, incidents: [] };
        entry.incidents.push(inc.incident_id);
        counts.set(key, entry);
      });
    });
    return [...counts.values()]
      .filter(e => e.incidents.length > 1)
      .sort((a, b) => b.incidents.length - a.incidents.length);
  }, [incidentsByUrgency]);

  // What the connected entities mean together. Read through the
  // evidence_graph contract with ATT&CK detection guidance retrieved for the
  // techniques in play, so the reading of the graph is grounded rather than
  // narrated. Requested per incident, not on every render.
  const [reading, setReading] = useState(null);
  const [readingState, setReadingState] = useState('idle');
  const [readingError, setReadingError] = useState('');

  useEffect(() => { setReading(null); setReadingState('idle'); setReadingError(''); },
    [current?.incident_id]);

  function readGraph() {
    if (!current) return;
    setReadingState('loading');
    api.enrichGraph({
      hosts: current.hosts, users: current.users, processes: current.processes,
      event_ids: current.event_ids,
      techniques_suspected: current.techniques_suspected,
      rules_fired: current.rules_fired,
      shared_entities: shared.slice(0, 6).map(e => `${e.kind}:${e.value}`),
    })
      .then(res => {
        if (res.ok && res.payload) { setReading(res); setReadingState('idle'); }
        else { setReadingError(res.error || 'no valid reading returned'); setReadingState('error'); }
      })
      .catch(err => { setReadingError(String(err.message || err)); setReadingState('error'); });
  }

  if (!isReady || !current) {
    return <p className="text-muted text-xs">No incidents to graph yet.</p>;
  }

  const caseFile = cases?.[current.incident_id];
  const nodes = buildGraph(current, caseFile);
  const risk = verdicts[current.incident_id]?.risk;

  return (
    <div className="flex gap-4 h-full">
      <div className="w-52 shrink-0 space-y-1 overflow-y-auto">
        <p className="text-muted text-[10px] uppercase tracking-wider px-1 mb-1">Incidents</p>
        {incidentsByUrgency.slice(0, 40).map(i => (
          <button key={i.incident_id} onClick={() => onSelect?.(i.incident_id)}
            className={`w-full text-left px-2 py-1.5 rounded transition-colors ${
              current.incident_id === i.incident_id ? 'bg-hover' : 'hover:bg-panel'}`}>
            <p className="text-primary text-[10px] font-mono truncate">{i.incident_id}</p>
            <p className="text-muted text-[10px] truncate">{i.hosts?.[0]}</p>
          </button>
        ))}
      </div>

      <div className="flex-1 min-w-0 space-y-3 overflow-y-auto">
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
            <Network size={13} className="text-blue-400" />
            <span className="text-muted text-[10px] uppercase tracking-wider">
              What this incident touches
            </span>
            {risk && (
              <span className="ml-auto text-muted text-[10px]">
                risk {risk.risk_score} ({risk.band})
              </span>
            )}
          </div>

          <div className="p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <FileWarning size={12} className="text-red-400" />
              <span className="text-primary text-xs font-mono">{current.incident_id}</span>
              <span className="text-muted text-[10px]">
                {current.alert_count} alert(s) · {String(current.first_seen).slice(0, 19)}
              </span>
            </div>
            {['host', 'user', 'process', 'ip', 'technique', 'rule', 'event'].map((k, i, arr) => (
              <Branch key={k} nodes={nodes} kind={k} last={i === arr.length - 1} />
            ))}
          </div>
        </div>

        {/* What the graph means, read by the agent through the
            evidence_graph contract. */}
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2 bg-panel border-b border-border">
            <Network size={13} className="text-emerald-400" />
            <span className="text-muted text-[10px] uppercase tracking-wider">
              What these connections mean
            </span>
            <button onClick={readGraph} disabled={readingState === 'loading'}
              className="ml-auto px-2 py-0.5 bg-hover border border-border rounded text-[10px] text-primary hover:border-blue-500 transition-colors disabled:opacity-50">
              {readingState === 'loading' ? 'Reading…' : reading ? 'Re-read' : 'Read the graph'}
            </button>
          </div>
          <div className="p-3 space-y-2">
            {readingState === 'idle' && !reading && (
              <p className="text-muted text-[10px]">
                Not yet read. The graph above is derived deterministically from the
                correlated incident; this asks the agent what the links mean together.
              </p>
            )}
            {readingState === 'loading' && (
              <p className="text-muted text-[10px]">Retrieving technique guidance and reading the graph…</p>
            )}
            {readingState === 'error' && (
              <p className="text-amber-400 text-[10px]">Could not read the graph — {readingError}</p>
            )}
            {reading && (
              <>
                <p className="text-primary text-xs leading-relaxed">{reading.payload.story}</p>
                <div>
                  <p className="text-muted text-[10px] uppercase tracking-wider">Key link</p>
                  <p className="text-primary text-[11px]">{reading.payload.key_link}</p>
                </div>
                {!!(reading.payload.pivot_next || []).length && (
                  <div>
                    <p className="text-muted text-[10px] uppercase tracking-wider">Pivot next</p>
                    {reading.payload.pivot_next.map((pv, i) => (
                      <p key={i} className="text-[11px]">
                        <span className="text-blue-400 font-mono">{pv.entity}</span>
                        <span className="text-muted"> — {pv.why}</span>
                      </p>
                    ))}
                  </div>
                )}
                {reading.payload.spread_risk && (
                  <p className="text-muted text-[10px]">
                    <span className="uppercase tracking-wider">Spread</span> — {reading.payload.spread_risk}
                  </p>
                )}
                <div className="pt-2 border-t border-border flex items-center gap-2 flex-wrap">
                  <span className="text-muted text-[9px] uppercase tracking-wider">Grounded in</span>
                  {(reading.knowledge_used || []).map(k => (
                    <span key={k.id} className="text-blue-400 text-[9px]">{k.id}</span>
                  ))}
                  <span className="ml-auto text-muted text-[9px]">
                    confidence {reading.payload.confidence} · {reading.elapsed_seconds}s
                  </span>
                </div>
              </>
            )}
          </div>
        </div>

        {/* The cross-incident view: one account or host appearing in several
            cases is how a campaign shows itself. */}
        {/* The header stays visible when collapsed. Previously the toggle
            lived inside the block it hid, so hiding removed the button too and
            the section could not be brought back without reloading. */}
        {shared.length > 0 && (
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <button
              type="button"
              onClick={() => setShowShared(v => !v)}
              aria-expanded={showShared}
              className="w-full flex items-center gap-2 px-3 py-2 bg-panel border-b border-border hover:bg-hover transition-colors text-left"
            >
              <Network size={13} className="text-amber-400" />
              <span className="text-muted text-[10px] uppercase tracking-wider">
                Entities appearing in more than one incident
              </span>
              <span className="text-amber-400 text-[10px]">{shared.length}</span>
              <span className="ml-auto flex items-center gap-1 text-muted text-[10px]">
                {showShared ? 'hide' : 'show'}
                <ChevronDown
                  size={12}
                  className={`transition-transform ${showShared ? '' : '-rotate-90'}`}
                />
              </span>
            </button>
            <div className="divide-y divide-border" hidden={!showShared}>
              {shared.slice(0, 8).map(e => {
                const Icon = KIND[e.kind].icon;
                return (
                  <div key={`${e.kind}:${e.value}`} className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      <Icon size={11} className={KIND[e.kind].tone} />
                      <span className="text-primary text-[11px] font-mono">{e.value}</span>
                      <span className="text-amber-400 text-[10px]">
                        in {e.incidents.length} incidents
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1 pl-4">
                      {e.incidents.slice(0, 6).map(id => (
                        <button key={id} onClick={() => onSelect?.(id)}
                          className="px-1.5 py-0.5 rounded bg-panel hover:bg-hover text-muted hover:text-primary text-[9px] font-mono">
                          {id}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="px-3 pb-2 text-muted text-[10px] leading-relaxed">
              An account or machine spanning several incidents is usually one
              intrusion moving, not several unrelated events.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
