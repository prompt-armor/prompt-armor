# Configuration

prompt-armor looks for configuration in this order:

1. Explicit path passed to `LiteEngine(config=load_config(path))`
2. `.prompt-armor.yml` in the current working directory
3. `~/.config/prompt-armor/.prompt-armor.yml`
4. Built-in defaults

## Generate a Template

```bash
prompt-armor config --init
```

## Configuration Options

```yaml
# Decision thresholds
thresholds:
  allow_below: 0.55     # Score below = ALLOW
  block_above: 0.7      # Score above = BLOCK
  hard_block: 0.95      # Any single layer above = instant BLOCK
  min_confidence: 0.5   # Below this = needs_council flag

# Analytics dashboard
analytics:
  enabled: false         # Set true to record to SQLite
  db_path: ~/.prompt-armor/analytics.db
  store_prompts: false   # Set true to see prompts in dashboard
  retention_days: 30
  max_records: 100000

# Council mode (optional LLM judge for uncertain cases)
council:
  enabled: false
  timeout_s: 5           # Max wait for LLM response
  fallback_decision: warn  # warn or block when LLM unavailable
  providers:
    - type: ollama       # ollama (local) or openrouter (future)
      model: phi3:mini
      base_url: http://localhost:11434
      privacy_mode: full  # full (local) or truncated (API)
```

## Threshold Profiles

### Conservative (fintech, healthcare)

```yaml
thresholds:
  allow_below: 0.15
  block_above: 0.5
  hard_block: 0.85
```

### Permissive (dev tools, creative apps)

```yaml
thresholds:
  allow_below: 0.4
  block_above: 0.85
  hard_block: 0.95
```
