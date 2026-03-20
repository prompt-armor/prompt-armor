"""MCP Server for llm-shield.

Exposes prompt security analysis as MCP tools that can be used
by Claude Desktop, Cursor, and other MCP-compatible clients.

Usage:
    llm-shield-mcp
"""

from __future__ import annotations

import io
import logging
import os
import sys

# Suppress noisy model loading output before any imports
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "llm-shield",
    instructions="LLM prompt security analysis — detect prompt injections, jailbreaks, and other attacks.",
)


def _get_engine():
    """Lazy-load the analysis engine."""
    from llm_shield.engine import LiteEngine

    if not hasattr(_get_engine, "_engine"):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            _get_engine._engine = LiteEngine()
        finally:
            sys.stdout = old_stdout
    return _get_engine._engine


@mcp.tool()
def analyze_prompt(prompt: str) -> dict:
    """Analyze a prompt for security risks including prompt injection, jailbreaks, and other LLM attacks.

    Args:
        prompt: The prompt text to analyze for security risks.

    Returns:
        Analysis result with risk_score, decision, categories, and evidence.
    """
    engine = _get_engine()
    result = engine.analyze(prompt)

    return {
        "risk_score": result.risk_score,
        "confidence": result.confidence,
        "decision": result.decision.value,
        "categories": [c.value for c in result.categories],
        "evidence": [
            {
                "layer": e.layer,
                "category": e.category.value,
                "description": e.description,
                "score": e.score,
            }
            for e in result.evidence
        ],
        "needs_council": result.needs_council,
        "latency_ms": result.latency_ms,
        "cost_usd": result.cost_usd,
    }


def main() -> None:
    """Start the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
