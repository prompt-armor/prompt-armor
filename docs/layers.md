# Analysis Layers

llm-shield uses 4 analysis layers that run **in parallel** for maximum speed.

## L1 — Regex Engine

**Latency:** < 1ms | **Dependencies:** None

Pattern matching against 40+ weighted regex rules with contextual modifiers. Rules are defined in `data/rules/default_rules.yml`.

Features:
- Weighted rules (0.0-1.0) per pattern
- Context modifiers reduce scores for quoted or educational content
- Convergence boost when multiple patterns match

## L2 — Classifier

**Latency:** < 5ms | **Dependencies:** onnxruntime (optional)

Sequence classifier for prompt injection detection. Currently uses a keyword-based heuristic; future versions will use a fine-tuned DistilBERT model via ONNX Runtime.

## L3 — Semantic Similarity

**Latency:** < 15ms | **Dependencies:** sentence-transformers, faiss-cpu

Compares prompt embeddings against a database of known attack embeddings using cosine similarity via FAISS. Detects paraphrased and novel variations of known attacks.

- Model: all-MiniLM-L6-v2 (22MB)
- Attack database: `data/attacks/known_attacks.jsonl`

## L4 — Structural Analysis

**Latency:** < 2ms | **Dependencies:** None

Analyzes structural features without looking at specific content:

- Instruction override ratio (imperative verb density)
- Delimiter injection detection
- Role assignment counting
- Privilege escalation signal density
- Encoding trick detection (base64, Unicode escapes, homoglyphs)
- URL counting (data exfiltration signals)

## Fusion

Combines layer scores using weighted averaging with:

- **Convergence boost:** When layers agree (low variance), confidence increases
- **Divergence penalty:** When layers disagree (high variance), confidence decreases
- **Hard block:** Any single layer at >= 0.95 triggers immediate BLOCK

## Gate

Decides if the Lite result is sufficient:

- Score below `allow_below` → ALLOW
- Score above `block_above` → BLOCK
- In between with high divergence → `needs_council=True`
