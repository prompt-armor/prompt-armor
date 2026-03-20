# CLI Reference

## Commands

### `prompt-shield analyze`

Analyze a single prompt for security risks.

```bash
prompt-shield analyze "Your prompt here"
prompt-shield analyze --file input.txt
prompt-shield analyze --json "prompt"
echo "prompt" | prompt-shield analyze
```

**Options:**
- `--file, -f` — Read prompt from file
- `--json` — Output as JSON
- `--verbose, -v` — Show detailed layer results
- `--config, -c` — Path to config YAML

**Exit codes:** 0=allow, 1=warn, 2=block, 3=error

### `prompt-shield scan`

Batch-scan prompt files in a directory.

```bash
prompt-shield scan --dir ./prompts/
prompt-shield scan --dir ./prompts/ --glob "*.md" --format json
```

**Options:**
- `--dir` — Directory to scan (required)
- `--glob` — File pattern (default: `*.txt`)
- `--format` — Output format: table, json, csv
- `--fail-on` — Exit non-zero if any file reaches this level (warn or block)

### `prompt-shield config`

Show or initialize configuration.

```bash
prompt-shield config --show
prompt-shield config --init
```

### `prompt-shield --version`

Show version.
