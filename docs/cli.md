# CLI Reference

## Commands

### `prompt-armor analyze`

Analyze a single prompt for security risks.

```bash
prompt-armor analyze "Your prompt here"
prompt-armor analyze --file input.txt
prompt-armor analyze --json "prompt"
echo "prompt" | prompt-armor analyze
```

**Options:**
- `--file, -f` — Read prompt from file
- `--json` — Output as JSON
- `--verbose, -v` — Show detailed layer results
- `--config, -c` — Path to config YAML

**Exit codes:** 0=allow, 1=warn, 2=block, 3=error

### `prompt-armor scan`

Batch-scan prompt files in a directory.

```bash
prompt-armor scan --dir ./prompts/
prompt-armor scan --dir ./prompts/ --glob "*.md" --format json
```

**Options:**
- `--dir` — Directory to scan (required)
- `--glob` — File pattern (default: `*.txt`)
- `--format` — Output format: table, json, csv
- `--fail-on` — Exit non-zero if any file reaches this level (warn or block)

### `prompt-armor config`

Show or initialize configuration.

```bash
prompt-armor config --show
prompt-armor config --init
```

### `prompt-armor --version`

Show version.
