# CLI Reference

## Commands

### `llm-shield analyze`

Analyze a single prompt for security risks.

```bash
llm-shield analyze "Your prompt here"
llm-shield analyze --file input.txt
llm-shield analyze --json "prompt"
echo "prompt" | llm-shield analyze
```

**Options:**
- `--file, -f` — Read prompt from file
- `--json` — Output as JSON
- `--verbose, -v` — Show detailed layer results
- `--config, -c` — Path to config YAML

**Exit codes:** 0=allow, 1=warn, 2=block, 3=error

### `llm-shield scan`

Batch-scan prompt files in a directory.

```bash
llm-shield scan --dir ./prompts/
llm-shield scan --dir ./prompts/ --glob "*.md" --format json
```

**Options:**
- `--dir` — Directory to scan (required)
- `--glob` — File pattern (default: `*.txt`)
- `--format` — Output format: table, json, csv
- `--fail-on` — Exit non-zero if any file reaches this level (warn or block)

### `llm-shield config`

Show or initialize configuration.

```bash
llm-shield config --show
llm-shield config --init
```

### `llm-shield --version`

Show version.
