import { useMemo } from 'react';
import { ExternalLink, ChevronRight, Shield } from 'lucide-react';
import { getMitreTechnique } from '../utils/mitreMapper';

// ── URL helpers ───────────────────────────────────────────────────────────────
const TACTIC_META = {
  TA0001: { name: 'Initial Access',    short: 'Init.Access', color: '#f97316', url: 'https://attack.mitre.org/tactics/TA0001/' },
  TA0002: { name: 'Execution',         short: 'Execution',   color: '#ef4444', url: 'https://attack.mitre.org/tactics/TA0002/' },
  TA0003: { name: 'Persistence',       short: 'Persistence', color: '#a855f7', url: 'https://attack.mitre.org/tactics/TA0003/' },
  TA0004: { name: 'Priv. Escalation',  short: 'PrivEsc',     color: '#ec4899', url: 'https://attack.mitre.org/tactics/TA0004/' },
  TA0005: { name: 'Defense Evasion',   short: 'DefEvasion',  color: '#8b5cf6', url: 'https://attack.mitre.org/tactics/TA0005/' },
  TA0006: { name: 'Credential Access', short: 'CredAccess',  color: '#3b82f6', url: 'https://attack.mitre.org/tactics/TA0006/' },
  TA0007: { name: 'Discovery',         short: 'Discovery',   color: '#06b6d4', url: 'https://attack.mitre.org/tactics/TA0007/' },
  TA0008: { name: 'Lateral Movement',  short: 'LateralMov',  color: '#10b981', url: 'https://attack.mitre.org/tactics/TA0008/' },
  TA0009: { name: 'Collection',        short: 'Collection',  color: '#84cc16', url: 'https://attack.mitre.org/tactics/TA0009/' },
  TA0010: { name: 'Exfiltration',      short: 'Exfil',       color: '#eab308', url: 'https://attack.mitre.org/tactics/TA0010/' },
  TA0011: { name: 'Command & Control', short: 'C2',          color: '#f59e0b', url: 'https://attack.mitre.org/tactics/TA0011/' },
  TA0040: { name: 'Impact',            short: 'Impact',      color: '#dc2626', url: 'https://attack.mitre.org/tactics/TA0040/' },
};

const TACTIC_ORDER = ['TA0001','TA0002','TA0003','TA0004','TA0005','TA0006','TA0007','TA0008','TA0009','TA0010','TA0011','TA0040'];

function getTechniqueUrl(id) {
  const parts = id.split('.');
  if (parts.length === 2) {
    return `https://attack.mitre.org/techniques/${parts[0]}/${parts[1].padStart(3, '0')}/`;
  }
  return `https://attack.mitre.org/techniques/${id}/`;
}

function getMitigationUrl(mCode) {
  return `https://attack.mitre.org/mitigations/${mCode}/`;
}

const TECHNIQUE_META = {
  'T1110.001': { tacticId: 'TA0006', mitigations: [{ id: 'M1032', name: 'Multi-factor Auth' }, { id: 'M1036', name: 'Account Policies' }] },
  'T1059.001': { tacticId: 'TA0002', mitigations: [{ id: 'M1042', name: 'Disable Feature' }, { id: 'M1045', name: 'Code Signing' }] },
  'T1021':     { tacticId: 'TA0008', mitigations: [{ id: 'M1035', name: 'Limit Access' }, { id: 'M1047', name: 'Audit' }] },
  'T1078':     { tacticId: 'TA0004', mitigations: [{ id: 'M1026', name: 'Privileged Accounts' }, { id: 'M1017', name: 'User Training' }] },
  'T1566':     { tacticId: 'TA0001', mitigations: [{ id: 'M1049', name: 'Antivirus' }, { id: 'M1031', name: 'Network IPS' }] },
  'T1486':     { tacticId: 'TA0040', mitigations: [{ id: 'M1053', name: 'Data Backup' }, { id: 'M1040', name: 'Behavior Prevention' }] },
  'T1041':     { tacticId: 'TA0010', mitigations: [{ id: 'M1031', name: 'Network IPS' }, { id: 'M1057', name: 'Data Loss Prevention' }] },
  'T1547':     { tacticId: 'TA0003', mitigations: [{ id: 'M1018', name: 'User Account Mgmt' }] },
  'T1190':     { tacticId: 'TA0001', mitigations: [{ id: 'M1048', name: 'App Isolation' }, { id: 'M1050', name: 'Exploit Protection' }] },
  'T1046':     { tacticId: 'TA0007', mitigations: [{ id: 'M1042', name: 'Disable Feature' }] },
  'T1204':     { tacticId: 'TA0002', mitigations: [{ id: 'M1038', name: 'Execution Prevention' }, { id: 'M1017', name: 'User Training' }] },
};

// ── Sub-components ────────────────────────────────────────────────────────────

function TacticPill({ tacticId, size = 'sm' }) {
  const meta = TACTIC_META[tacticId];
  if (!meta) return null;
  const px = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';
  return (
    <a
      href={meta.url}
      target="_blank"
      rel="noopener noreferrer"
      title={`MITRE ATT&CK Tactic: ${meta.name}`}
      className={`inline-flex items-center gap-1 rounded font-semibold uppercase tracking-wide transition-opacity hover:opacity-80 ${px}`}
      style={{ background: `${meta.color}22`, border: `1px solid ${meta.color}55`, color: meta.color }}
      onClick={e => e.stopPropagation()}
    >
      {size === 'sm' ? meta.short : meta.name}
    </a>
  );
}

function TechniqueLink({ id, name }) {
  return (
    <a
      href={getTechniqueUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      title={`MITRE ATT&CK Technique: ${id} — ${name}`}
      className="font-mono text-xs text-blue-400 hover:text-blue-300 hover:underline transition-colors"
      onClick={e => e.stopPropagation()}
    >
      {id}
    </a>
  );
}

function AttackButton({ id, name }) {
  return (
    <a
      href={getTechniqueUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      title={`Open ${id} on ATT&CK`}
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-blue-500/40 text-blue-400 text-[10px] hover:bg-blue-500/10 transition-colors"
      onClick={e => e.stopPropagation()}
    >
      ↗ ATT&CK
    </a>
  );
}

function MitigationChip({ id, name }) {
  return (
    <a
      href={getMitigationUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      title={`MITRE Mitigation: ${id} — ${name}`}
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-green-500/30 text-green-400 text-[10px] bg-green-500/10 hover:bg-green-500/20 transition-colors font-mono"
      onClick={e => e.stopPropagation()}
    >
      {id}
      <span className="font-sans text-green-300 text-[9px] truncate max-w-[80px]">{name}</span>
    </a>
  );
}

function TechniqueCard({ technique, name, count, meta }) {
  const tacticMeta = meta?.tacticId ? TACTIC_META[meta.tacticId] : null;
  const mitigations = meta?.mitigations || [];

  return (
    <div className="bg-card border border-border rounded-lg p-3 flex flex-col gap-2 hover:border-blue-500/40 transition-colors">
      {/* Card header row */}
      <div className="flex items-center gap-2 flex-wrap">
        {tacticMeta && <TacticPill tacticId={meta.tacticId} size="sm" />}
        <TechniqueLink id={technique} name={name} />
        <span className="text-primary text-xs font-medium flex-1 min-w-0 truncate">{name}</span>
        <AttackButton id={technique} name={name} />
      </div>

      {/* Count badge + mitigations */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-hover border border-border text-muted">
          {count} event{count !== 1 ? 's' : ''}
        </span>
        {mitigations.map(m => (
          <MitigationChip key={m.id} id={m.id} name={m.name} />
        ))}
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

export default function MitreCards({ logs }) {
  const { techniques, chainTactics } = useMemo(() => {
    const counts = {};
    for (const log of (logs || [])) {
      const { technique, name } = getMitreTechnique(log.rule, log.message);
      if (!counts[technique]) counts[technique] = { name, count: 0 };
      counts[technique].count++;
    }

    const techniques = Object.entries(counts)
      .map(([id, { name, count }]) => ({ id, name, count, meta: TECHNIQUE_META[id] || null }))
      .sort((a, b) => {
        const oa = a.meta ? TACTIC_ORDER.indexOf(a.meta.tacticId) : 99;
        const ob = b.meta ? TACTIC_ORDER.indexOf(b.meta.tacticId) : 99;
        return oa !== ob ? oa - ob : b.count - a.count;
      });

    const tacticsSeen = new Set(techniques.map(t => t.meta?.tacticId).filter(Boolean));
    const chainTactics = TACTIC_ORDER.filter(tid => tacticsSeen.has(tid));

    return { techniques, chainTactics };
  }, [logs]);

  if (!techniques.length) {
    return (
      <div className="flex items-center justify-center py-8 text-muted text-xs">
        <Shield size={16} className="mr-2 opacity-40" /> No MITRE techniques detected
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Attack chain banner */}
      {chainTactics.length > 0 && (
        <div className="bg-card border border-border rounded-lg p-3">
          <p className="text-muted text-[10px] uppercase tracking-wider mb-2">Observed Attack Chain</p>
          <div className="flex items-center flex-wrap gap-1">
            {chainTactics.map((tid, idx) => (
              <div key={tid} className="flex items-center gap-1">
                <TacticPill tacticId={tid} size="md" />
                {idx < chainTactics.length - 1 && <ChevronRight size={12} className="text-muted shrink-0" />}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technique cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {techniques.map(t => (
          <TechniqueCard
            key={t.id}
            technique={t.id}
            name={t.name}
            count={t.count}
            meta={t.meta}
          />
        ))}
      </div>

      {/* Legend bar */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 bg-panel rounded border border-border text-[10px] text-muted">
        <span className="font-medium text-primary mr-1">Legend:</span>
        <span className="inline-flex items-center gap-1">
          <span className="px-1.5 py-0.5 rounded font-semibold" style={{ background: '#3b82f622', border: '1px solid #3b82f655', color: '#3b82f6' }}>Tactic</span>
          clickable tactic category
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="font-mono text-blue-400">T1234</span>
          technique ID link
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="px-1.5 py-0.5 rounded border border-blue-500/40 text-blue-400">↗ ATT&CK</span>
          opens MITRE page
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="px-1.5 py-0.5 rounded border border-green-500/30 text-green-400 font-mono bg-green-500/10">M1032</span>
          mitigation link
        </span>
      </div>
    </div>
  );
}
