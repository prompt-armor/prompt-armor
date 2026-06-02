"""Tests for the L3 persisted FAISS index cache (cold-start optimization).

The cache lets L3 skip re-embedding the whole attack corpus (~tens of seconds)
when the attack DB and model are unchanged. These tests exercise the cache
layer directly with a tiny synthetic index — no ONNX model required.
"""

from __future__ import annotations

import numpy as np
import pytest

from prompt_armor.layers import l3_similarity

faiss = pytest.importorskip("faiss")


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Redirect the module's cache paths into a temp dir (no real ~/.prompt-armor writes)."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(l3_similarity, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(l3_similarity, "_INDEX_CACHE_PATH", cache_dir / "l3_faiss_index.bin")
    monkeypatch.setattr(l3_similarity, "_INDEX_META_PATH", cache_dir / "l3_index_meta.json")
    return cache_dir


def _tiny_index(n: int = 5, dim: int = 8):
    idx = faiss.IndexFlatIP(dim)
    rng = np.random.default_rng(0)
    vecs = rng.random((n, dim)).astype("float32")
    idx.add(vecs)
    return idx, vecs


def test_sig_is_deterministic_and_content_sensitive(tmp_path):
    attacks = tmp_path / "attacks.jsonl"
    attacks.write_text('{"text":"a"}\n')
    model = tmp_path / "model.onnx"
    model.write_bytes(b"\x00" * 100)

    s1 = l3_similarity._index_cache_sig(attacks, model)
    s2 = l3_similarity._index_cache_sig(attacks, model)
    assert s1 is not None and s1 == s2

    # Changing the attack DB content must change the signature (cache invalidation).
    attacks.write_text('{"text":"a"}\n{"text":"b"}\n')
    assert l3_similarity._index_cache_sig(attacks, model) != s1


def test_sig_none_on_missing_input(tmp_path):
    assert l3_similarity._index_cache_sig(tmp_path / "nope.jsonl", tmp_path / "nope.onnx") is None


def test_roundtrip_save_load(tmp_cache):
    idx, vecs = _tiny_index()
    meta = [{"category": "jailbreak", "source": "x"}, {"category": "leak", "source": "y"}]
    l3_similarity._save_index_cache("sig123", idx, meta)

    loaded = l3_similarity._load_index_cache("sig123")
    assert loaded is not None
    loaded_idx, loaded_meta = loaded
    assert loaded_idx.ntotal == idx.ntotal
    assert loaded_meta == meta
    # Cached index returns the same nearest-neighbor distances as the original.
    q = vecs[:1]
    assert np.allclose(idx.search(q, 1)[0], loaded_idx.search(q, 1)[0])


def test_load_returns_none_on_sig_mismatch(tmp_cache):
    idx, _ = _tiny_index()
    l3_similarity._save_index_cache("sigA", idx, [])
    assert l3_similarity._load_index_cache("sigB") is None


def test_load_returns_none_when_absent(tmp_cache):
    assert l3_similarity._load_index_cache("anything") is None


def test_save_is_best_effort(tmp_cache, monkeypatch):
    """A write failure must not raise — caching is a pure optimization."""

    def _boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(faiss, "write_index", _boom)
    idx, _ = _tiny_index()
    l3_similarity._save_index_cache("sig", idx, [])  # must not raise
    assert not l3_similarity._INDEX_CACHE_PATH.exists()
