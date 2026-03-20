# Analysis Layers

llm-shield uses 4 analysis layers that run **in parallel**, combined by a trained meta-classifier.

```
INPUT → NORMALIZE → SEGMENT → [L1 | L2 | L3 | L4] → META-CLASSIFIER → DECISION
```

## Preprocessing

Before any layer runs:

1. **Unicode NFKC normalization** — resolves homoglyphs and compatibility characters
2. **Zero-width character stripping** — removes invisible chars used to break regex patterns
3. **Whitespace collapse** — normalizes excessive spacing
4. **Sliding window** — for prompts > 150 words, segments into overlapping windows (200 words, stride 100) and analyzes each independently, taking the max score. Catches compound injections.

## L1 — Regex Engine

**Latency:** < 1ms | **Dependencies:** None

60+ weighted regex rules covering 8 attack categories in 5 languages (EN, DE, ES, FR, PT). Rules are defined in `data/rules/default_rules.yml`.

Features:
- Weighted rules (0.0-1.0) per pattern
- Context modifiers reduce scores for quoted or educational content (hardened against exploitation — high-confidence matches are never dampened)
- ReDoS-safe patterns (bounded quantifiers)

## L2 — DeBERTa Classifier

**Latency:** 3-7ms | **Dependencies:** onnxruntime

DeBERTa-v3-xsmall (22M params) fine-tuned for prompt injection classification. Runs via ONNX Runtime on CPU.

- Auto-downloads from HuggingFace Hub on first use (83MB, pinned by commit SHA)
- Score calibration: raw model output (0.23-0.78 range) stretched to 0.0-1.0
- Falls back to keyword heuristic if ONNX model is not available
- The **dominant signal** in the meta-classifier (highest coefficient)

## L3 — Semantic Similarity

**Latency:** 10-20ms | **Dependencies:** sentence-transformers, faiss-cpu

Compares prompt embeddings against a database of 1,151 known attack embeddings using cosine similarity via FAISS.

- Model: `paraphrase-multilingual-MiniLM-L12-v2` (50+ languages)
- Attack database: `data/attacks/known_attacks.jsonl`
- Detects paraphrased and novel variations of known attacks

## L4 — Structural Analysis

**Latency:** < 2ms | **Dependencies:** None

Analyzes structural features without looking at specific content:

- Instruction override ratio (imperative verb density, tiered weighting)
- Delimiter injection detection (system tags, markdown boundaries)
- Role assignment counting (expanded patterns with benign role whitelist)
- Privilege escalation signal density
- Encoding trick detection (base64, Unicode escapes, homoglyphs)
- URL counting (data exfiltration signals)

## Meta-Classifier Fusion

A trained logistic regression model combines all 4 layer scores with interaction features:

**Input features (9):**
- 4 raw layer scores (L1, L2, L3, L4)
- Max score across layers
- Min score across layers
- L1 × L4 interaction (regex + structural agreement)
- L2 × L3 interaction (ML + similarity agreement)
- Number of layers with score > 0.1

The meta-classifier learned that:
- **L2 is the dominant signal** — semantic understanding catches what rules cannot
- **Number of agreeing layers** is the second strongest signal
- L3/L4 coefficients are clamped to non-negative to prevent adversarial exploitation

**Output:** Risk score (0.0-1.0) via sigmoid, thresholded into ALLOW / WARN / BLOCK.

## Decision Gate

- Score < 0.53 → **ALLOW**
- Score 0.53-0.80 → **WARN**
- Score ≥ 0.80 → **BLOCK**
- Any single layer ≥ 0.95 → instant **BLOCK** (hard block)

## Fail-Open Design

Each layer has a 2-second timeout. If a layer hangs or crashes, it is skipped and analysis continues with remaining layers. If all ML layers fail, L1 (regex) and L4 (structural) still provide basic detection.
