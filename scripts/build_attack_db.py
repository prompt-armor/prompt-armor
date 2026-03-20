#!/usr/bin/env python3
"""Build the attack database from public datasets.

Downloads and curates prompt injection/jailbreak datasets from HuggingFace
and other sources into a single known_attacks.jsonl file.

Usage:
    python scripts/build_attack_db.py
    python scripts/build_attack_db.py --output src/llm_shield/data/attacks/known_attacks.jsonl
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Add src to path so we can import llm_shield for auto-categorization
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

DEFAULT_OUTPUT = Path(__file__).parent.parent / "src" / "llm_shield" / "data" / "attacks" / "known_attacks.jsonl"

# Category mapping for auto-categorization
CATEGORY_KEYWORDS = {
    "jailbreak": [
        "DAN", "STAN", "jailbreak", "do anything now", "no restrictions",
        "no limitations", "no filters", "unfiltered", "uncensored", "unrestricted",
        "developer mode", "god mode", "admin mode", "without restrictions",
        "pretend you", "act as", "roleplay", "you are now", "two responses",
        "dual response", "evil", "no ethical", "no moral", "bypass safety",
    ],
    "prompt_injection": [
        "ignore previous", "ignore all", "disregard", "forget your",
        "override", "new instructions", "actual instructions", "real instructions",
        "from now on", "instead do", "do not follow", "scratch that",
    ],
    "system_prompt_leak": [
        "system prompt", "initial prompt", "repeat your", "show your instructions",
        "what were you told", "print everything above", "reveal your",
        "hidden instructions", "secret instructions", "original prompt",
    ],
    "identity_override": [
        "you are no longer", "forget that you are", "your name is now",
        "you are not", "stop being", "new identity", "new persona",
    ],
    "data_exfiltration": [
        "send to", "forward to", "email to", "http://", "https://",
        "hidden link", "hidden image", "markdown image", "exfiltrate",
    ],
    "social_engineering": [
        "i am the developer", "i am the admin", "authorized test",
        "security audit", "urgent override", "emergency", "i work for",
        "openai employee", "anthropic employee",
    ],
    "encoding_attack": [
        "base64", "rot13", "hex", "unicode", "\\u00", "decode this",
        "translate from binary", "ascii art",
    ],
    "instruction_bypass": [
        "<|im_start|>", "<|im_end|>", "[SYSTEM]", "[/SYSTEM]",
        "### system", "### user", "### assistant", "<|endoftext|>",
    ],
}


def classify_prompt(text: str) -> str:
    """Auto-classify a prompt into a category based on keyword matching."""
    text_lower = text.lower()
    scores: dict[str, int] = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in text_lower)
        if score > 0:
            scores[category] = score
    if scores:
        return max(scores, key=scores.get)  # type: ignore[arg-type]
    return "prompt_injection"  # fallback


def normalize_text(text: str) -> str:
    """Clean up prompt text."""
    text = text.strip()
    # Remove excessive whitespace
    text = " ".join(text.split())
    return text


def dedup_key(text: str) -> str:
    """Create a dedup key from normalized text."""
    normalized = text.lower().strip()
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def load_existing(path: Path) -> list[dict]:
    """Load existing entries, filtering out benign."""
    entries = []
    if path.exists():
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("category") != "benign":
                    entries.append(entry)
    return entries


def fetch_deepset_injections() -> list[dict]:
    """Fetch deepset/prompt-injections dataset."""
    print("  Fetching deepset/prompt-injections...")
    try:
        from datasets import load_dataset
        ds = load_dataset("deepset/prompt-injections", split="train")
        entries = []
        for row in ds:
            if row["label"] == 1:  # injection
                text = normalize_text(row["text"])
                if 10 < len(text) < 2000:
                    entries.append({
                        "text": text,
                        "category": classify_prompt(text),
                        "source": "deepset/prompt-injections",
                    })
        print(f"    Got {len(entries)} injection prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_trustai_jailbreaks() -> list[dict]:
    """Fetch TrustAIRLab/in-the-wild-jailbreak-prompts."""
    print("  Fetching TrustAIRLab/in-the-wild-jailbreak-prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset(
            "TrustAIRLab/in-the-wild-jailbreak-prompts",
            "jailbreak_2023_12_25",
            split="train",
        )
        entries = []
        for row in ds:
            if not row.get("jailbreak", False):
                continue
            text = normalize_text(row.get("prompt", ""))
            if 10 < len(text) < 2000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "trustai/in-the-wild",
                })
        print(f"    Got {len(entries)} jailbreak prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_chatgpt_jailbreaks() -> list[dict]:
    """Fetch rubend18/ChatGPT-Jailbreak-Prompts."""
    print("  Fetching rubend18/ChatGPT-Jailbreak-Prompts...")
    try:
        from datasets import load_dataset
        ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
        entries = []
        for row in ds:
            text = normalize_text(row.get("Prompt", ""))
            if 10 < len(text) < 3000:  # jailbreaks can be longer
                entries.append({
                    "text": text,
                    "category": "jailbreak",
                    "source": "jailbreakchat",
                })
        print(f"    Got {len(entries)} jailbreak prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def fetch_gandalf() -> list[dict]:
    """Fetch Lakera/gandalf_ignore_instructions."""
    print("  Fetching Lakera/gandalf_ignore_instructions...")
    try:
        from datasets import load_dataset
        ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
        entries = []
        for row in ds:
            text = normalize_text(row.get("text", ""))
            if 10 < len(text) < 2000:
                entries.append({
                    "text": text,
                    "category": classify_prompt(text),
                    "source": "lakera/gandalf",
                })
        print(f"    Got {len(entries)} prompts")
        return entries
    except Exception as e:
        print(f"    Failed: {e}")
        return []


def build_attack_db(output_path: Path | None = None) -> None:
    """Build the complete attack database."""
    output_path = output_path or DEFAULT_OUTPUT

    print("=" * 60)
    print("Building attack database")
    print("=" * 60)

    # Load existing curated entries
    print("\n1. Loading existing entries...")
    existing = load_existing(output_path)
    print(f"   Loaded {len(existing)} existing entries (benign removed)")

    # Fetch from all sources
    print("\n2. Fetching from public datasets...")
    all_new: list[dict] = []
    all_new.extend(fetch_deepset_injections())
    all_new.extend(fetch_trustai_jailbreaks())
    all_new.extend(fetch_chatgpt_jailbreaks())
    all_new.extend(fetch_gandalf())

    print(f"\n   Total fetched: {len(all_new)} new entries")

    # Combine existing + new
    combined = existing + all_new

    # Deduplicate
    print("\n3. Deduplicating...")
    seen: set[str] = set()
    unique: list[dict] = []
    for entry in combined:
        key = dedup_key(entry["text"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    print(f"   Unique entries: {len(unique)} (removed {len(combined) - len(unique)} duplicates)")

    # Balance categories — cap each at 30% of total, sample extras
    print("\n4. Balancing categories...")
    by_category: dict[str, list[dict]] = {}
    for entry in unique:
        cat = entry["category"]
        by_category.setdefault(cat, []).append(entry)

    max_per_category = max(int(len(unique) * 0.30), 50)
    balanced: list[dict] = []
    for cat, entries in sorted(by_category.items()):
        if len(entries) > max_per_category:
            # Keep diverse subset: sort by length to get variety, take every Nth
            entries.sort(key=lambda e: len(e["text"]))
            step = len(entries) / max_per_category
            sampled = [entries[int(i * step)] for i in range(max_per_category)]
            balanced.extend(sampled)
            print(f"   {cat}: {len(entries)} → {len(sampled)} (capped)")
        else:
            balanced.extend(entries)
            print(f"   {cat}: {len(entries)}")

    # Write output
    print(f"\n5. Writing {len(balanced)} entries to {output_path}")
    with open(output_path, "w") as f:
        for entry in balanced:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # Summary
    print("\n" + "=" * 60)
    print(f"DONE — {len(balanced)} entries written")
    final_cats: dict[str, int] = {}
    for entry in balanced:
        cat = entry["category"]
        final_cats[cat] = final_cats.get(cat, 0) + 1
    for cat, count in sorted(final_cats.items()):
        pct = count / len(balanced) * 100
        print(f"  {cat}: {count} ({pct:.1f}%)")

    sources: dict[str, int] = {}
    for entry in balanced:
        src = entry["source"]
        sources[src] = sources.get(src, 0) + 1
    print("\nSources:")
    for src, count in sorted(sources.items(), key=lambda x: -x[1]):
        print(f"  {src}: {count}")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build llm-shield attack database")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output JSONL path")
    args = parser.parse_args()
    build_attack_db(args.output)
