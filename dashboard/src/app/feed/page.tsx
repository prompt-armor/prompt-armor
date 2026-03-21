"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

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
}

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

  useEffect(() => {
    async function fetchData() {
      try {
        const res = await fetch(`/api/feed?decision=${filter}&limit=100`);
        setAnalyses(await res.json());
      } catch { /* ignore */ }
    }
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, [filter]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span style={{ color: '#1f521f' }}>$</span>
          <h1 className="text-sm uppercase tracking-widest glow">tail -f /var/log/armor.log</h1>
        </div>
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

      <div className="terminal-window">
        <div className="terminal-header">+--- LOG OUTPUT ---+</div>
        <div className="p-2 space-y-0 text-[11px] leading-relaxed max-h-[calc(100vh-180px)] overflow-auto">
          {analyses.length === 0 ? (
            <div className="py-8 text-center" style={{ color: '#1f521f' }}>
              <p>waiting for data...</p>
              <p className="mt-2 cursor-blink"><span style={{ color: '#1f521f' }}>$ </span></p>
            </div>
          ) : (
            analyses.map((a) => {
              const cats = JSON.parse(a.categories || "[]") as string[];
              const ts = a.timestamp.slice(11, 19) || a.timestamp;
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
