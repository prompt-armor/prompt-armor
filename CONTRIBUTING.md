# Contributing to prompt-armor

Thanks for your interest in contributing! Here's how you can help.

## Quick Start

```bash
git clone https://github.com/prompt-armor/prompt-armor
cd prompt-armor
pip install -e ".[dev,ml,mcp]"
pytest tests/ -v
```

## Ways to Contribute

### Add Attack Samples (Easiest)

The most impactful contribution is expanding the attack database. Add entries to:

- `src/prompt_armor/data/attacks/known_attacks.jsonl` — Known attack prompts for L3 similarity matching
- `tests/benchmark/dataset/malicious.jsonl` — Labeled attack prompts for benchmarking

Format:
```json
{"text": "the attack prompt", "category": "prompt_injection", "source": "your_source"}
```

Categories: `prompt_injection`, `jailbreak`, `identity_override`, `system_prompt_leak`, `instruction_bypass`, `data_exfiltration`, `encoding_attack`, `social_engineering`

### Add Regex Rules

Add patterns to `src/prompt_armor/data/rules/default_rules.yml`. Each rule needs:
- Unique ID (e.g., `PI-011` for prompt injection rule 11)
- Regex pattern (case-insensitive by default)
- Category, weight (0.0-1.0), and description

Multilingual rules are welcome (DE, ES, FR, PT, and any other language).

### Bug Fixes and Improvements

1. Fork the repo
2. Branch from `dev`: `git checkout dev && git checkout -b fix/your-fix`
3. Make your changes
4. Ensure tests pass: `pytest tests/ -v`
5. Ensure lint passes: `ruff check src/ tests/`
6. Submit a PR **targeting `dev`** (not `main`)

## Development

```bash
# Run tests
pytest tests/ -v

# Run a single test
pytest tests/unit/test_l1_regex.py -v

# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/prompt_armor/

# Run benchmark
python tests/benchmark/run_benchmark.py
```

## Code Style

- Python 3.10+
- Formatted with `ruff`
- Type hints on all public functions
- `dataclass(frozen=True, slots=True)` for result types
- `Pydantic` only for config validation

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new functionality
- Update the benchmark if you change detection logic
- Run `ruff check` and `pytest` before submitting
