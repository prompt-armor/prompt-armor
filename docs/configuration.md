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
# Layer weights (normalized to sum to 1.0 for active layers)
weights:
  l1_regex: 0.20        # Regex pattern matching
  l2_classifier: 0.30   # ML/heuristic classifier
  l3_similarity: 0.30   # Semantic similarity to known attacks
  l4_structural: 0.20   # Structural feature analysis

# Decision thresholds
thresholds:
  allow_below: 0.3      # Score below = ALLOW
  block_above: 0.7      # Score above = BLOCK
  hard_block: 0.95      # Any single layer above = instant BLOCK
  min_confidence: 0.5   # Below this = needs_council flag

# Fusion tuning
convergence_boost: 0.10    # Boost when layers agree
divergence_penalty: 0.15   # Penalty when layers disagree
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
