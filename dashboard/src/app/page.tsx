import { getOverviewStats, getTopCategories } from "@/lib/db";

export const dynamic = "force-dynamic";

function AsciiBar({ value, max, width = 24, color = "#33ff00" }: { value: number; max: number; width?: number; color?: string }) {
  const filled = Math.round((value / Math.max(max, 1)) * width);
  const empty = width - filled;
  return (
    <span className="ascii-bar" style={{ color }}>
      [{"█".repeat(filled)}{"░".repeat(empty)}]
    </span>
  );
}

function TerminalCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="terminal-window">
      <div className="terminal-header">+--- {title} ---+</div>
      <div className="p-3">{children}</div>
    </div>
  );
}

export default function OverviewPage() {
  let stats;
  let categories;

  try {
    stats = getOverviewStats();
    categories = getTopCategories();
  } catch {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="terminal-window max-w-md p-6 text-center">
          <p className="glow mb-2">[ERR] NO DATA</p>
          <p className="text-xs" style={{ color: '#1f521f' }}>
            Enable analytics in .prompt-armor.yml:
          </p>
          <pre className="mt-3 text-left text-[11px] p-3" style={{ color: '#ffb000', background: '#111' }}>
{`analytics:
  enabled: true`}
          </pre>
        </div>
      </div>
    );
  }

  const blockRate = stats.total > 0 ? ((stats.block / stats.total) * 100) : 0;
  const warnRate = stats.total > 0 ? ((stats.warn / stats.total) * 100) : 0;
  const allowRate = stats.total > 0 ? ((stats.allow / stats.total) * 100) : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <span style={{ color: '#1f521f' }}>$</span>
        <h1 className="text-sm uppercase tracking-widest glow">system status</h1>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <TerminalCard title="SCANS">
          <div className="text-2xl font-bold glow">{stats.total.toLocaleString()}</div>
          <div className="text-[10px] mt-1" style={{ color: '#1f521f' }}>[24h] {stats.today}</div>
        </TerminalCard>

        <TerminalCard title="BLOCK RATE">
          <div className="text-2xl font-bold" style={{ color: stats.block > 0 ? '#ff3333' : '#33ff00' }}>
            {blockRate.toFixed(1)}%
          </div>
          <div className="text-[10px] mt-1" style={{ color: '#1f521f' }}>{stats.block} threats</div>
        </TerminalCard>

        <TerminalCard title="LATENCY">
          <div className="text-2xl font-bold glow">{stats.avgLatency.toFixed(0)}<span className="text-sm">ms</span></div>
          <div className="text-[10px] mt-1" style={{ color: '#1f521f' }}>avg p/request</div>
        </TerminalCard>

        <TerminalCard title="BLOCKS/HOUR">
          <div className="text-2xl font-bold" style={{ color: stats.blocksLastHour > 0 ? '#ff3333' : '#33ff00' }}>
            {stats.blocksLastHour}
          </div>
          <div className="text-[10px] mt-1" style={{ color: '#1f521f' }}>
            {stats.blocksLastHour > 5 ? '[!!] spike detected' : 'last 60 min'}
          </div>
        </TerminalCard>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <TerminalCard title="DECISION DISTRIBUTION">
          <div className="space-y-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-14 text-right" style={{ color: '#33ff00' }}>ALLOW</span>
              <AsciiBar value={stats.allow} max={stats.total} color="#33ff00" />
              <span style={{ color: '#1f521f' }}>{allowRate.toFixed(1)}%</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-14 text-right" style={{ color: '#ffb000' }}>WARN</span>
              <AsciiBar value={stats.warn} max={stats.total} color="#ffb000" />
              <span style={{ color: '#1f521f' }}>{warnRate.toFixed(1)}%</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-14 text-right" style={{ color: '#ff3333' }}>BLOCK</span>
              <AsciiBar value={stats.block} max={stats.total} color="#ff3333" />
              <span style={{ color: '#1f521f' }}>{blockRate.toFixed(1)}%</span>
            </div>
          </div>
        </TerminalCard>

        <TerminalCard title="TOP THREAT CATEGORIES">
          {categories.length === 0 ? (
            <p className="text-xs" style={{ color: '#1f521f' }}>[OK] no threats detected</p>
          ) : (
            <div className="space-y-1 text-xs">
              {categories.map((cat, i) => (
                <div key={cat.category} className="flex items-center gap-2">
                  <span style={{ color: '#1f521f' }}>{String(i + 1).padStart(2, '0')}.</span>
                  <span className="flex-1" style={{ color: '#33ff00' }}>
                    {cat.category}
                    <span style={{ color: '#1f521f' }}>
                      {" " + ".".repeat(Math.max(1, 30 - cat.category.length)) + " "}
                    </span>
                  </span>
                  <span className="font-bold" style={{ color: '#ffb000' }}>{cat.count}</span>
                </div>
              ))}
            </div>
          )}
        </TerminalCard>
      </div>
    </div>
  );
}
