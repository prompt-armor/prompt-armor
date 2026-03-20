# Integrations

Pre-built integrations for prompt-armor with popular platforms.

## OpenClaw

### Plugin (recommended)

Full plugin with automatic message interception, manual scan tool, and agent-level skill.

```bash
pip install prompt-armor
openclaw plugins install @prompt-armor/openclaw-plugin
```

See [openclaw-plugin/README.md](openclaw-plugin/README.md) for configuration and details.

### Skill (standalone)

Lightweight skill for ClawHub. Teaches the agent to scan external content manually.

```bash
clawhub install prompt-armor
```

See [openclaw/SKILL.md](openclaw/SKILL.md) for documentation.

## MCP Server

Already included in the main package. Run:

```bash
prompt-armor-mcp
```

Works with Claude Desktop, Cursor, and any MCP-compatible client.

## More Integrations (coming soon)

- LangChain callback handler
- FastAPI middleware
- Open WebUI filter
