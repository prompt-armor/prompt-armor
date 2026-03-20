# MCP Server

prompt-shield provides an [MCP](https://modelcontextprotocol.io/) server for integration with Claude Desktop, Cursor, and other MCP-compatible clients.

## Starting the Server

```bash
prompt-shield-mcp
```

## Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "prompt-shield": {
      "command": "prompt-shield-mcp"
    }
  }
}
```

## Available Tools

### `analyze_prompt`

Analyze a prompt for security risks.

**Parameters:**
- `prompt` (string, required) — The prompt text to analyze

**Returns:**
```json
{
  "risk_score": 0.87,
  "confidence": 0.91,
  "decision": "block",
  "categories": ["prompt_injection"],
  "evidence": [...],
  "needs_council": false,
  "latency_ms": 12.3,
  "cost_usd": 0.0
}
```
