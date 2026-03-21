"use client";

import { useEffect, useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface TimelinePoint {
  hour: string;
  allow: number;
  warn: number;
  block: number;
}

export default function TimelinePage() {
  const [data, setData] = useState<TimelinePoint[]>([]);
  const [hours, setHours] = useState(24);

  useEffect(() => {
    async function fetchData() {
      try {
        const res = await fetch(`/api/timeline?hours=${hours}`);
        setData(await res.json());
      } catch { /* ignore */ }
    }
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [hours]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span style={{ color: '#1f521f' }}>$</span>
          <h1 className="text-sm uppercase tracking-widest glow">history --graph</h1>
        </div>
        <div className="flex gap-1">
          {[6, 12, 24, 48, 168].map((h) => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className="px-2 py-0.5 text-[10px] border transition-colors"
              style={{
                borderColor: hours === h ? '#33ff00' : '#1f521f',
                color: hours === h ? '#0a0a0a' : '#33ff00',
                background: hours === h ? '#33ff00' : 'transparent',
              }}
            >
              {h < 24 ? `${h}h` : `${h / 24}d`}
            </button>
          ))}
        </div>
      </div>

      <div className="terminal-window">
        <div className="terminal-header">+--- ANALYSIS VOLUME ---+</div>
        <div className="p-4">
          {data.length === 0 ? (
            <div className="py-12 text-center" style={{ color: '#1f521f' }}>
              <p>no data points in range</p>
              <p className="mt-1 cursor-blink text-xs"><span style={{ color: '#1f521f' }}>$ </span></p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={400}>
              <AreaChart data={data}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f521f" />
                <XAxis
                  dataKey="hour"
                  tick={{ fontSize: 10, fill: '#1f521f', fontFamily: 'JetBrains Mono' }}
                  tickFormatter={(v: string) => {
                    if (!v) return "";
                    // Show time portion: "16:00" or "16:10" or just date for >48h
                    return v.length > 10 ? v.slice(11) : v.slice(5);
                  }}
                  stroke="#1f521f"
                  interval="preserveStartEnd"
                />
                <YAxis
                  tick={{ fontSize: 10, fill: '#1f521f', fontFamily: 'JetBrains Mono' }}
                  stroke="#1f521f"
                />
                <Tooltip
                  labelFormatter={(v) => String(v)}
                  contentStyle={{
                    fontSize: 11,
                    fontFamily: 'JetBrains Mono',
                    background: '#0d0d0d',
                    border: '1px solid #1f521f',
                    borderRadius: 0,
                    color: '#33ff00',
                  }}
                  itemStyle={{ color: '#33ff00' }}
                />
                <Area type="stepAfter" dataKey="allow" stackId="1" fill="#33ff00" stroke="#33ff00" fillOpacity={0.15} />
                <Area type="stepAfter" dataKey="warn" stackId="1" fill="#ffb000" stroke="#ffb000" fillOpacity={0.3} />
                <Area type="stepAfter" dataKey="block" stackId="1" fill="#ff3333" stroke="#ff3333" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
