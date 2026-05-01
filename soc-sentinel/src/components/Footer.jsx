export default function Footer({ logs }) {
  const loaded = logs && logs.length > 0;
  const critical = loaded ? logs.filter(l => l.severity === 'CRITICAL').length : 0;

  return (
    <footer className="h-[44px] flex items-center justify-between px-4 border-t border-border bg-panel text-muted text-xs shrink-0">
      <div className="flex items-center gap-4">
        <span className={loaded ? 'text-green-500' : 'text-muted'}>
          {loaded ? `● ${logs.length.toLocaleString()} events loaded` : '○ No data loaded'}
        </span>
        {loaded && critical > 0 && (
          <span className="text-red-400">▲ {critical} critical</span>
        )}
      </div>
      <div className="flex items-center gap-4">
        <span>SOC Sentinel v1.0</span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block animate-pulse2" />
          AI Ready
        </span>
      </div>
    </footer>
  );
}
