"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { formatLocalDateTime } from "@/lib/utils";

interface Analysis {
  id: number;
  timestamp: string;
  prompt_hash: string;
  prompt_text: string | null;
  prompt_length: number;
  risk_score: number;
  confidence: number;
  decision: string;
  categories: string;
  evidence: string;
  layer_scores: string;
  latency_ms: number;
  needs_council: number;
  lite_decision: string | null;
  council_decision: string | null;
  council_reasoning: string | null;
  council_confidence: string | null;
  council_model: string | null;
  council_latency_ms: number;
}

function AsciiScoreBar({ score, width = 22 }: { score: number; width?: number }) {
  const filled = Math.round(score * width);
  const empty = width - filled;
  const color = score < 0.3 ? "#33ff00" : score < 0.7 ? "#ffb000" : "#ff3333";
  return (
    <span style={{ color, letterSpacing: '-1px' }}>
      {"█".repeat(filled)}{"░".repeat(empty)}
    </span>
  );
}

function DecisionTag({ decision }: { decision: string }) {
  const styles: Record<string, { label: string; color: string }> = {
    allow: { label: "[OK]", color: "#33ff00" },
    warn: { label: "[!!]", color: "#ffb000" },
    block: { label: "[ERR]", color: "#ff3333" },
  };
  const s = styles[decision] || styles.allow;
  return <span className="text-lg font-bold" style={{ color: s.color, textShadow: `0 0 8px ${s.color}50` }}>{s.label}</span>;
}

function AnalysisContent() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    fetch(`/api/analysis?id=${id}`)
      .then((r) => r.json())
      .then((d) => { if (d.error) setError(d.error); else setAnalysis(d); })
      .catch(() => setError("connection failed"));
  }, [id]);

  if (!id) return <p style={{ color: '#1f521f' }}>[ERR] no analysis id</p>;
  if (error) return <p style={{ color: '#ff3333' }}>[ERR] {error}</p>;
  if (!analysis) return <p style={{ color: '#1f521f' }}>loading...</p>;

  const categories = JSON.parse(analysis.categories || "[]") as string[];
  const evidence = JSON.parse(analysis.evidence || "[]") as Array<{ layer: string; category: string; description: string; score: number }>;
  const layerScores = JSON.parse(analysis.layer_scores || "{}") as Record<string, number>;

  return (
    <div className="space-y-4 max-w-3xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span style={{ color: '#1f521f' }}>$</span>
          <h1 className="text-sm uppercase tracking-widest glow">inspect --id {analysis.id}</h1>
        </div>
        <DecisionTag decision={analysis.decision} />
      </div>

      <div className="terminal-window">
        <div className="terminal-header">+--- THREAT ASSESSMENT ---+</div>
        <div className="p-4 space-y-2 text-xs">
          <div className="flex items-center gap-2">
            <span className="w-16 text-right" style={{ color: '#1f521f' }}>RISK</span>
            <AsciiScoreBar score={analysis.risk_score} />
            <span className="font-bold" style={{ color: analysis.risk_score > 0.7 ? '#ff3333' : analysis.risk_score > 0.3 ? '#ffb000' : '#33ff00' }}>
              {analysis.risk_score.toFixed(4)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-16 text-right" style={{ color: '#1f521f' }}>CONF</span>
            <AsciiScoreBar score={analysis.confidence} />
            <span style={{ color: '#33ff00' }}>{analysis.confidence.toFixed(4)}</span>
          </div>
        </div>
      </div>

      <div className="terminal-window">
        <div className="terminal-header">+--- METADATA ---+</div>
        <div className="p-4 space-y-1 text-xs">
          <div><span style={{ color: '#1f521f' }}>timestamp .. </span>{formatLocalDateTime(analysis.timestamp)}</div>
          <div><span style={{ color: '#1f521f' }}>latency ... </span>{analysis.latency_ms.toFixed(1)}ms</div>
          <div><span style={{ color: '#1f521f' }}>length .... </span>{analysis.prompt_length} chars</div>
          <div><span style={{ color: '#1f521f' }}>hash ...... </span>{analysis.prompt_hash}</div>
          {analysis.council_decision ? (
            <div style={{ color: '#00ccff' }}>[OK] council verdict rendered</div>
          ) : analysis.needs_council === 1 ? (
            <div style={{ color: '#ffb000' }}>[!!] council recommended</div>
          ) : null}
          {categories.length > 0 && (
            <div>
              <span style={{ color: '#1f521f' }}>categories  </span>
              {categories.map((c) => (
                <span key={c} className="mr-2" style={{ color: '#ffb000' }}>[{c}]</span>
              ))}
            </div>
          )}
        </div>
      </div>

      {analysis.council_decision && (
        <div className="terminal-window">
          <div className="terminal-header" style={{ color: '#00ccff' }}>+--- COUNCIL VERDICT ---+</div>
          <div className="p-4 space-y-1 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-16 text-right" style={{ color: '#1f521f' }}>JUDGMENT</span>
              <span className="font-bold text-sm" style={{
                color: analysis.council_decision === 'SAFE' ? '#33ff00'
                  : analysis.council_decision === 'MALICIOUS' ? '#ff3333'
                  : '#ffb000',
                textShadow: `0 0 8px ${
                  analysis.council_decision === 'SAFE' ? '#33ff0050'
                  : analysis.council_decision === 'MALICIOUS' ? '#ff333350'
                  : '#ffb00050'
                }`,
              }}>
                {analysis.council_decision}
              </span>
              <span style={{ color: '#1f521f' }}>
                ({analysis.council_confidence})
              </span>
            </div>
            {analysis.lite_decision && analysis.lite_decision !== analysis.decision && (
              <div className="flex items-center gap-2">
                <span className="w-16 text-right" style={{ color: '#1f521f' }}>OVERRIDE</span>
                <span style={{ color: analysis.lite_decision === 'allow' ? '#33ff00' : analysis.lite_decision === 'block' ? '#ff3333' : '#ffb000' }}>
                  {analysis.lite_decision.toUpperCase()}
                </span>
                <span style={{ color: '#00ccff' }}>→</span>
                <span style={{ color: analysis.decision === 'allow' ? '#33ff00' : analysis.decision === 'block' ? '#ff3333' : '#ffb000' }}>
                  {analysis.decision.toUpperCase()}
                </span>
              </div>
            )}
            <div>
              <span style={{ color: '#1f521f' }}>model ..... </span>
              <span style={{ color: '#00ccff' }}>{analysis.council_model}</span>
            </div>
            <div>
              <span style={{ color: '#1f521f' }}>reasoning . </span>
              <span style={{ color: '#33ff00' }}>{analysis.council_reasoning}</span>
            </div>
            <div>
              <span style={{ color: '#1f521f' }}>latency ... </span>
              {analysis.council_latency_ms.toFixed(0)}ms
            </div>
          </div>
        </div>
      )}

      {Object.keys(layerScores).length > 0 && (
        <div className="terminal-window">
          <div className="terminal-header">+--- LAYER SCORES ---+</div>
          <div className="p-4 space-y-1 text-xs">
            {Object.entries(layerScores).map(([layer, score]) => (
              <div key={layer} className="flex items-center gap-2">
                <span className="w-24" style={{ color: '#1f521f' }}>
                  {layer} {".".repeat(Math.max(1, 16 - layer.length))}
                </span>
                <span style={{ color: '#33ff00' }}>{score.toFixed(4)}</span>
                <AsciiScoreBar score={score} />
              </div>
            ))}
          </div>
        </div>
      )}

      {evidence.length > 0 && (
        <div className="terminal-window">
          <div className="terminal-header">+--- EVIDENCE LOG ---+</div>
          <div className="p-4 space-y-1 text-[11px]">
            {evidence.map((e, i) => (
              <div key={i}>
                <span style={{ color: '#1f521f' }}>&gt; </span>
                <span style={{ color: '#ffb000' }}>{e.layer}</span>
                <span style={{ color: '#1f521f' }}>: </span>
                <span style={{ color: '#33ff00' }}>{e.description}</span>
                <span style={{ color: '#1f521f' }}> ({e.score.toFixed(2)})</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {analysis.prompt_text && (
        <div className="terminal-window">
          <div className="terminal-header" style={{ color: '#ffb000' }}>+--- RAW INPUT [SENSITIVE] ---+</div>
          <div className="p-4">
            <pre className="text-[11px] whitespace-pre-wrap break-all" style={{ color: '#33ff00' }}>
              {analysis.prompt_text}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AnalysisPage() {
  return (
    <Suspense fallback={<p style={{ color: '#1f521f' }}>loading...</p>}>
      <AnalysisContent />
    </Suspense>
  );
}
