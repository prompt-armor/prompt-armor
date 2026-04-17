#!/usr/bin/env python3
"""Semantic deduplication + quality filtering of attack DB.

Addresses the jayavibhav 327K analysis finding: 83% of FPs come from L3
matching generic attack DB entries against benign prompts.

Pipeline:
1. Load known_attacks.jsonl (25,160 entries)
2. Encode with L3 ONNX model (reuse existing)
3. Prune short satml-ctf entries (< 120 chars, no attack keywords)
4. Compute specificity per entry: 1 - max_cos_to_benign(5K benign pool)
5. Drop entries with specificity < 0.35 (too generic)
6. Greedy semantic dedup @ cosine >= 0.92 (keep highest specificity rep)
7. Output: known_attacks_v2.jsonl + manifest

Usage:
    python scripts/dedup_attacks_semantic.py
    python scripts/dedup_attacks_semantic.py --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np

os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

ATTACKS_PATH = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks.jsonl"
OUTPUT_PATH = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks_v2.jsonl"
MANIFEST_PATH = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "attacks" / "manifest.json"
BENIGN_SAMPLE = Path(__file__).parent.parent / "tests" / "benchmark" / "dataset" / "benign.jsonl"

# Short entry pruning: keep satml-ctf entries only if they have attack keywords
_ATTACK_KEYWORDS = frozenset({
    "ignore", "forget", "disregard", "override", "bypass", "disable",
    "instructions", "prompt", "system", "previous", "above", "rules",
    "pretend", "roleplay", "jailbreak", "dan", "unrestricted",
    "decode", "base64", "reveal", "leak", "exfiltrate",
})


def has_attack_keywords(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in _ATTACK_KEYWORDS)


def load_attack_db() -> list[dict]:
    entries = []
    with open(ATTACKS_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def load_benign_pool(max_samples: int = 2000) -> list[str]:
    """Load a benign reference pool for specificity scoring."""
    texts = []
    if BENIGN_SAMPLE.exists():
        with open(BENIGN_SAMPLE) as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    text = entry.get("text", "").strip()
                    if text:
                        texts.append(text)
    # Add from jayavibhav if available locally
    jayavibhav_sample = Path(__file__).parent.parent / "internal" / "jayavibhav_test_1k.jsonl"
    if jayavibhav_sample.exists():
        with open(jayavibhav_sample) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("label", 1) == 0:
                    text = entry.get("text", "").strip()
                    if text:
                        texts.append(text)
    return texts[:max_samples]


def encode_texts(texts: list[str], engine) -> np.ndarray:
    """Encode texts using L3 ONNX model (reuse engine infrastructure)."""
    l3_layer = None
    for layer in engine._layers:
        if layer.name == "l3_similarity":
            l3_layer = layer
            break
    if l3_layer is None:
        raise RuntimeError("L3 layer not found in engine")

    if not l3_layer._use_onnx:
        raise RuntimeError("L3 ONNX not available")

    # Batch encode
    return l3_layer._encode_onnx(texts)


def main(dry_run: bool = False):
    print("=" * 70)
    print("Attack DB Semantic Dedup + Quality Filtering")
    print("=" * 70)

    # 1. Load
    print("\n[1/7] Loading attack DB...")
    entries = load_attack_db()
    print(f"      Loaded {len(entries)} entries")

    # 2. Short entry pruning (satml-ctf without keywords)
    print("\n[2/7] Pruning short entries...")
    pruned = []
    pruned_count = 0
    for e in entries:
        text = e.get("text", "")
        source = e.get("source", "unknown")
        # Very short entries without keywords are noise
        if len(text) < 120 and not has_attack_keywords(text):
            pruned_count += 1
            continue
        # satml-ctf especially noisy when short
        if source == "satml-ctf-2024" and len(text) < 150 and not has_attack_keywords(text):
            pruned_count += 1
            continue
        pruned.append(e)
    print(f"      Pruned {pruned_count} entries → {len(pruned)} remaining")

    # 3. Initialize engine for encoding
    print("\n[3/7] Loading L3 model for encoding...")
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        from prompt_armor.config import ShieldConfig
        from prompt_armor.engine import LiteEngine

        engine = LiteEngine(config=ShieldConfig())
    finally:
        sys.stdout = old_stdout
    print(f"      Active layers: {engine.active_layers}")

    # 4. Encode attack texts (cached)
    print(f"\n[4/7] Encoding {len(pruned)} attack texts...")
    emb_cache = Path(__file__).parent.parent / "internal" / "attack_embeddings_cache.npy"
    if emb_cache.exists() and not dry_run:
        attack_embs = np.load(emb_cache)
        if attack_embs.shape[0] == len(pruned):
            print(f"      Using cached embeddings from {emb_cache.name}")
        else:
            print("      Cache stale (shape mismatch), re-encoding...")
            t0 = time.time()
            attack_texts = [e["text"] for e in pruned]
            attack_embs = encode_texts(attack_texts, engine)
            print(f"      Encoded in {time.time() - t0:.1f}s, shape={attack_embs.shape}")
            np.save(emb_cache, attack_embs)
    else:
        t0 = time.time()
        attack_texts = [e["text"] for e in pruned]
        attack_embs = encode_texts(attack_texts, engine)
        print(f"      Encoded in {time.time() - t0:.1f}s, shape={attack_embs.shape}")
        emb_cache.parent.mkdir(exist_ok=True)
        np.save(emb_cache, attack_embs)

    # 5. Specificity scoring vs benign pool (informational only)
    print("\n[5/7] Computing specificity vs benign pool (info)...")
    benign_texts = load_benign_pool()
    print(f"      Benign pool: {len(benign_texts)} samples")
    benign_embs = encode_texts(benign_texts, engine)

    import faiss

    dim = attack_embs.shape[1]
    benign_index = faiss.IndexFlatIP(dim)
    benign_index.add(benign_embs.astype(np.float32))

    # For each attack, find max cos to any benign
    benign_sim, _ = benign_index.search(attack_embs.astype(np.float32), 1)
    specificity = 1.0 - benign_sim[:, 0]
    print(f"      Specificity: mean={specificity.mean():.3f}, median={np.median(specificity):.3f}")
    print(f"      Entries with specificity < 0.10: {(specificity < 0.10).sum()} (near-benign clones)")
    print(f"      Entries with specificity < 0.05: {(specificity < 0.05).sum()} (indistinguishable)")

    # Filter only the most extreme cases (near-benign clones)
    keep_mask = specificity >= 0.05
    filtered_idx = np.where(keep_mask)[0]
    print(f"      After near-benign filter (>=0.05): {len(filtered_idx)} entries")

    # 6. Semantic dedup (greedy, highest-specificity first)
    print("\n[6/7] Semantic deduplication (cosine >= 0.92)...")
    # Sort by specificity descending (keep most-specific representative)
    order = filtered_idx[np.argsort(-specificity[filtered_idx])]

    kept_indices = []
    kept_index = faiss.IndexFlatIP(dim)

    for i in order:
        emb = attack_embs[i : i + 1].astype(np.float32)
        if kept_index.ntotal > 0:
            sims, _ = kept_index.search(emb, 1)
            if sims[0, 0] >= 0.92:
                continue  # duplicate of a better entry
        kept_index.add(emb)
        kept_indices.append(i)

    print(f"      After dedup: {len(kept_indices)} entries")

    # 7. Write output + manifest
    print("\n[7/7] Writing output...")
    if dry_run:
        print("      [DRY RUN] Skipping file writes")
    else:
        with open(OUTPUT_PATH, "w") as f:
            for idx, i in enumerate(kept_indices):
                entry = dict(pruned[i])
                entry["id"] = f"a{idx:06d}"
                entry["specificity"] = round(float(specificity[i]), 4)
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"      Written to {OUTPUT_PATH}")

        # Manifest
        sha = hashlib.sha256(OUTPUT_PATH.read_bytes()).hexdigest()[:16]
        source_counts: dict[str, int] = {}
        for i in kept_indices:
            src = pruned[i].get("source", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1

        manifest = {
            "version": "v2",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "original_count": len(entries),
            "pruned_short": pruned_count,
            "filtered_generic": len(pruned) - len(filtered_idx),
            "final_count": len(kept_indices),
            "reduction_pct": round(100 * (1 - len(kept_indices) / len(entries)), 1),
            "sha256_16": sha,
            "sources": source_counts,
        }
        with open(MANIFEST_PATH, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"      Manifest: {MANIFEST_PATH}")

    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Original:        {len(entries)}")
    print(f"  After pruning:   {len(pruned)} (-{pruned_count})")
    print(f"  After filter:    {len(filtered_idx)} (-{len(pruned) - len(filtered_idx)})")
    print(f"  After dedup:     {len(kept_indices)}")
    print(f"  Reduction:       {100 * (1 - len(kept_indices) / len(entries)):.1f}%")

    engine.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(dry_run=args.dry_run)
