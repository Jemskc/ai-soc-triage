export default function KPICard({ label, value, icon: Icon, color = '#3b82f6', sub }) {
  return (
    <div className="bg-card border border-border rounded-lg p-4 flex flex-col gap-2 animate-fadeIn">
      <div className="flex items-center justify-between">
        <span className="text-muted text-xs uppercase tracking-wider">{label}</span>
        {Icon && <Icon size={16} style={{ color }} />}
      </div>
      <div className="text-2xl font-semibold text-primary" style={{ color }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {sub && <div className="text-muted text-xs">{sub}</div>}
    </div>
  );
}
