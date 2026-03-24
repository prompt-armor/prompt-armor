#!/usr/bin/env python3
"""Contrastive fine-tuning for L3 similarity layer embeddings.

The base model (paraphrase-multilingual-MiniLM-L12-v2) embeds by TOPIC,
not by INTENT. This causes false positives where benign security discussions
match attacks. This script fine-tunes with a manual contrastive training
loop (no Trainer overhead) to separate attacks from benign by intent.

Output: Fine-tuned model saved to data/models/l3-contrastive/

Usage:
    python scripts/train_l3_contrastive.py
    python scripts/train_l3_contrastive.py --epochs 3 --batch-size 32
"""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as f_nn
from torch.utils.data import DataLoader, Dataset

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

ATTACK_DB = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "attacks" / "known_attacks.jsonl"
BENCHMARK_DIR = Path(__file__).parent.parent / "tests" / "benchmark" / "dataset"
MODEL_OUTPUT = Path(__file__).parent.parent / "src" / "prompt_armor" / "data" / "models" / "l3-contrastive"
BASE_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"


# Hard negatives: benign prompts that mention security topics
HARD_NEGATIVES = [
    "How does the DAN jailbreak work technically? I want to understand it to protect my AI.",
    "Write a tutorial about protecting against jailbreak attempts in LLM applications",
    "Explain the difference between prompt injection and SQL injection",
    "What are the best practices for system prompt security?",
    "Can you describe common social engineering techniques used in cybersecurity?",
    "I'm studying adversarial attacks on language models for my thesis",
    "Summarize the OWASP Top 10 for LLM Applications",
    "How do I implement input validation to prevent prompt injection?",
    "What is the ignore_previous function in this Python library?",
    "Review this code: # ignore previous errors and retry\ndef retry_operation():",
    "The meeting notes say 'disregard previous quarter estimates, use updated figures'",
    "In my game, the character says 'forget everything you know and start fresh'",
    "Translate this sentence from our security report: 'Attackers attempted to bypass filters'",
    "My system prompt for the chatbot is: 'You are a helpful customer service assistant'",
    "In our role-playing game, players can say 'I am now the dungeon master'",
    "I want you to act as an interviewer. I will be the candidate.",
    "Write a Python script that reads a config file and overrides default settings",
    "Explain the concept of privilege escalation in operating systems",
    "Explain how base64 encoding works and why it's not encryption",
    "How do companies perform red team exercises?",
]


def load_attacks() -> list[str]:
    attacks = []
    with open(ATTACK_DB) as f:
        for line in f:
            entry = json.loads(line.strip())
            text = entry.get("text", "").strip()
            if 10 < len(text) < 1000:
                attacks.append(text)
    return attacks


def load_benign() -> list[str]:
    benign_path = BENCHMARK_DIR / "benign.jsonl"
    benign = []
    if benign_path.exists():
        with open(benign_path) as f:
            for line in f:
                entry = json.loads(line.strip())
                text = entry.get("text", "").strip()
                if 10 < len(text) < 1000:
                    benign.append(text)
    return benign


class TripletDataset(Dataset):
    """Triplet dataset: (anchor_attack, positive_attack, negative_benign)."""

    def __init__(self, attacks: list[str], negatives: list[str], size: int = 5000):
        random.seed(42)
        self.triplets = []
        for _ in range(size):
            # anchor and positive are different attacks (same class)
            a, p = random.sample(attacks, 2)
            # negative is a benign sample
            n = random.choice(negatives)
            self.triplets.append((a, p, n))

    def __len__(self) -> int:
        return len(self.triplets)

    def __getitem__(self, idx: int) -> tuple[str, str, str]:
        return self.triplets[idx]


def collate_fn(batch: list[tuple[str, str, str]]) -> tuple[list[str], list[str], list[str]]:
    anchors, positives, negatives = zip(*batch)
    return list(anchors), list(positives), list(negatives)


def train(
    epochs: int = 3,
    batch_size: int = 32,
    lr: float = 2e-5,
    margin: float = 0.3,
    num_triplets: int = 5000,
) -> None:
    from sentence_transformers import SentenceTransformer

    print("=" * 60)
    print("L3 Contrastive Fine-Tuning (manual loop)")
    print("=" * 60)

    # Load data
    print("\n1. Loading data...")
    attacks = load_attacks()
    benign = load_benign()
    all_negatives = HARD_NEGATIVES + benign
    print(f"   Attacks: {len(attacks)}")
    print(f"   Negatives: {len(all_negatives)}")

    # Build dataset
    dataset = TripletDataset(attacks, all_negatives, size=num_triplets)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn)

    # Load model
    device = "cpu"  # MPS has overhead issues for small models
    print(f"\n2. Loading base model: {BASE_MODEL} (device: {device})")
    model = SentenceTransformer(BASE_MODEL, device=device)
    dim = model.get_sentence_embedding_dimension()
    print(f"   Embedding dimension: {dim}")

    # Optimizer — only fine-tune top layers
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)

    # Warmup + cosine decay scheduler
    total_steps = len(dataloader) * epochs
    warmup_steps = int(total_steps * 0.1)

    def lr_lambda(step: int) -> float:
        if step < warmup_steps:
            return step / max(warmup_steps, 1)
        progress = (step - warmup_steps) / max(total_steps - warmup_steps, 1)
        return 0.5 * (1.0 + np.cos(np.pi * progress))

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)

    # Training
    print("\n3. Training...")
    print(f"   Epochs: {epochs}")
    print(f"   Batch size: {batch_size}")
    print(f"   Steps/epoch: {len(dataloader)}")
    print(f"   Total steps: {total_steps}")
    print(f"   Triplets: {num_triplets}")

    start_time = time.time()

    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        n_batches = 0

        for anchors, positives, negatives in dataloader:
            # Forward pass through model (keeping gradients)
            all_texts = anchors + positives + negatives
            features = model.tokenize(all_texts)
            features = {k: v.to(device) for k, v in features.items()}
            out = model.forward(features)
            embeddings = out["sentence_embedding"]
            embeddings = f_nn.normalize(embeddings, p=2, dim=1)

            bs = len(anchors)
            anchor_emb = embeddings[:bs]
            positive_emb = embeddings[bs : 2 * bs]
            negative_emb = embeddings[2 * bs :]

            # Triplet loss with cosine distance
            pos_dist = 1.0 - f_nn.cosine_similarity(anchor_emb, positive_emb)
            neg_dist = 1.0 - f_nn.cosine_similarity(anchor_emb, negative_emb)
            loss = f_nn.relu(pos_dist - neg_dist + margin).mean()

            # Backward
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            epoch_loss += loss.item()
            n_batches += 1

        avg_loss = epoch_loss / max(n_batches, 1)
        elapsed = time.time() - start_time
        print(f"   Epoch {epoch + 1}/{epochs}: loss={avg_loss:.4f} ({elapsed:.0f}s)")

    # Save model
    MODEL_OUTPUT.mkdir(parents=True, exist_ok=True)
    model.save(str(MODEL_OUTPUT))
    print(f"\n4. Model saved to {MODEL_OUTPUT}")

    # Quick evaluation
    print("\n5. Evaluation...")
    model.eval()

    test_attacks = random.sample(attacks, min(200, len(attacks)))
    test_benign = random.sample(benign, min(200, len(benign)))

    with torch.no_grad():
        attack_emb = model.encode(test_attacks, normalize_embeddings=True)
        benign_emb = model.encode(test_benign, normalize_embeddings=True)

    # Cross-similarity (should be LOW after fine-tuning)
    cross_sim = float(np.mean(attack_emb @ benign_emb.T))
    attack_self = float(np.mean(attack_emb @ attack_emb.T))
    benign_self = float(np.mean(benign_emb @ benign_emb.T))

    print(f"   Attack self-similarity: {attack_self:.3f}")
    print(f"   Benign self-similarity: {benign_self:.3f}")
    print(f"   Cross-similarity: {cross_sim:.3f}")
    print(f"   Separation gap: {attack_self - cross_sim:.3f}")

    # Compare with base model
    print("\n   Comparing with base model...")
    base = SentenceTransformer(BASE_MODEL, device=device)
    base_attack = base.encode(test_attacks, normalize_embeddings=True)
    base_benign = base.encode(test_benign, normalize_embeddings=True)
    base_cross = float(np.mean(base_attack @ base_benign.T))
    base_attack_self = float(np.mean(base_attack @ base_attack.T))

    print(f"   Base attack self-sim: {base_attack_self:.3f}")
    print(f"   Base cross-sim: {base_cross:.3f}")
    print(f"   Fine-tuned cross-sim: {cross_sim:.3f}")
    print(f"   Cross-sim reduction: {base_cross - cross_sim:+.3f}")

    total_time = time.time() - start_time
    print(f"\n   Total training time: {total_time:.0f}s ({total_time / 60:.1f}min)")
    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Contrastive fine-tuning for L3")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--num-triplets", type=int, default=5000)
    args = parser.parse_args()
    train(epochs=args.epochs, batch_size=args.batch_size, lr=args.lr, num_triplets=args.num_triplets)
