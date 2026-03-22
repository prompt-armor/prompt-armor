"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { formatLocalTime } from "@/lib/utils";

interface Analysis {
  id: number;
  timestamp: string;
  decision: string;
  risk_score: number;
  categories: string;
  latency_ms: number;
  prompt_length: number;
  prompt_text: string | null;
  prompt_hash: string;
  council_decision: string | null;
}

const REFRESH_OPTIONS = [
  { label: "off", ms: 0 },
  { label: "1s", ms: 1000 },
  { label: "2s", ms: 2000 },
  { label: "5s", ms: 5000 },
  { label: "10s", ms: 10000 },
  { label: "30s", ms: 30000 },
  { label: "60s", ms: 60000 },
];

function DecisionTag({ decision }: { decision: string }) {
  const styles: Record<string, { label: string; color: string }> = {
    allow: { label: "[OK ]", color: "#33ff00" },
    warn:  { label: "[!! ]", color: "#ffb000" },
    block: { label: "[ERR]", color: "#ff3333" },
  };
  const s = styles[decision] || styles.allow;
  return <span className="font-bold" style={{ color: s.color }}>{s.label}</span>;
}

export default function FeedPage() {
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [filter, setFilter] = useState("all");
  const [refreshMs, setRefreshMs] = useState(0); // start paused
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch(`/api/feed?decision=${filter}&limit=100`);
      setAnalyses(await res.json());
    } catch { /* ignore */ }
  }, [filter]);

  // Fetch once on mount and when filter changes
  useEffect(() => { fetchData(); }, [fetchData]);

  // Auto-refresh interval
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (refreshMs > 0) {
      intervalRef.current = setInterval(fetchData, refreshMs);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [refreshMs, fetchData]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span style={{ color: '#1f521f' }}>$</span>
          <h1 className="text-sm uppercase tracking-widest glow">tail -f /var/log/armor.log</h1>
        </div>
        <div className="flex gap-3">
          {/* Refresh rate selector */}
          <div className="flex gap-0.5 items-center">
            <span className="text-[9px] mr-1" style={{ color: '#1f521f' }}>REFRESH:</span>
            {REFRESH_OPTIONS.map((opt) => (
              <button
                key={opt.label}
                onClick={() => setRefreshMs(opt.ms)}
                className="px-1.5 py-0.5 text-[9px] uppercase border transition-colors"
                style={{
                  borderColor: refreshMs === opt.ms ? '#00ccff' : '#1f521f',
                  color: refreshMs === opt.ms ? '#0a0a0a' : '#00ccff',
                  background: refreshMs === opt.ms ? '#00ccff' : 'transparent',
                }}
              >
                {opt.label}
              </button>
            ))}
          </div>
          {/* Decision filter */}
          <div className="flex gap-1">
            {["all", "allow", "warn", "block"].map((d) => {
              const colors: Record<string, string> = { all: "#33ff00", allow: "#33ff00", warn: "#ffb000", block: "#ff3333" };
              return (
                <button
                  key={d}
                  onClick={() => setFilter(d)}
                  className="px-2 py-0.5 text-[10px] uppercase border transition-colors"
                  style={{
                    borderColor: filter === d ? colors[d] : '#1f521f',
                    color: filter === d ? '#0a0a0a' : colors[d],
                    background: filter === d ? colors[d] : 'transparent',
                  }}
                >
                  {d === "all" ? "--all" : `--${d}`}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="terminal-window">
        <div className="terminal-header">
          +--- LOG OUTPUT ---+
          {refreshMs > 0 && (
            <span style={{ color: '#00ccff', marginLeft: 8, fontSize: '9px' }}>
              [LIVE {refreshMs / 1000}s]
            </span>
          )}
          {refreshMs === 0 && (
            <span style={{ color: '#1f521f', marginLeft: 8, fontSize: '9px' }}>
              [PAUSED]
            </span>
          )}
        </div>
        <div className="p-2 space-y-0 text-[11px] leading-relaxed max-h-[calc(100vh-180px)] overflow-auto">
          {analyses.length === 0 ? (
            <div className="py-8 text-center" style={{ color: '#1f521f' }}>
              <p>waiting for data...</p>
              <p className="mt-2 cursor-blink"><span style={{ color: '#1f521f' }}>$ </span></p>
            </div>
          ) : (
            analyses.map((a) => {
              const ts = formatLocalTime(a.timestamp);
              const scoreColor = a.risk_score < 0.3 ? "#33ff00" : a.risk_score < 0.7 ? "#ffb000" : "#ff3333";

              return (
                <Link
                  key={a.id}
                  href={`/analysis?id=${a.id}`}
                  className="flex gap-2 px-2 py-0.5 hover:bg-[#1f521f]/20 transition-colors cursor-pointer"
                  style={{ color: '#33ff00' }}
                >
                  <span style={{ color: '#1f521f' }}>[{ts}]</span>
                  <DecisionTag decision={a.decision} />
                  {a.council_decision && (
                    <span style={{ color: '#00ccff', fontSize: '9px' }} title={`Council: ${a.council_decision}`}>
                      [C]
                    </span>
                  )}
                  <span style={{ color: scoreColor }}>
                    {a.risk_score.toFixed(2)}
                  </span>
                  <span className="flex-1 truncate" style={{ color: a.decision === 'allow' ? '#1f521f' : '#33ff00' }}>
                    {a.prompt_text
                      ? a.prompt_text.slice(0, 60) + (a.prompt_text.length > 60 ? "…" : "")
                      : `[${a.prompt_hash || "no text"}]`}
                  </span>
                  <span className="shrink-0" style={{ color: '#1f521f' }}>
                    {a.latency_ms.toFixed(0)}ms
                  </span>
                </Link>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
