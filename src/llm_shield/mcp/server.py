"""MCP Server for llm-shield.

Exposes prompt security analysis as MCP tools that can be used
by Claude Desktop, Cursor, and other MCP-compatible clients.

Usage:
    llm-shield-mcp
"""

from __future__ import annotations

import functools
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


@functools.lru_cache(maxsize=1)
def _get_engine():
    """Lazy-load the analysis engine. Thread-safe via lru_cache."""
    from llm_shield.engine import LiteEngine

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return LiteEngine()
    finally:
        sys.stdout = old_stdout


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
    return result.to_dict()


def main() -> None:
    """Start the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
