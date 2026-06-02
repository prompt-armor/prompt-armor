"""Tests for the L3 persisted FAISS index (cold-start optimization).

Covers the cache helpers (signature, save/load round-trip, best-effort failure)
and the bundled index that ships in the wheel. The committed bundled index is
verified to match the current attack DB + pinned model revision, so a DB/model
change that forgets to regenerate it fails CI.
"""

from __future__ import annotations

import numpy as np
import pytest

from prompt_armor.layers import l3_similarity

faiss = pytest.importorskip("faiss")


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Redirect the user-cache paths into a temp dir (no real ~/.prompt-armor writes)."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(l3_similarity, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(l3_similarity, "_USER_INDEX_PATH", cache_dir / "l3_faiss_index.bin")
    monkeypatch.setattr(l3_similarity, "_USER_META_PATH", cache_dir / "l3_index_meta.json")
    return cache_dir


def _tiny_index(n: int = 5, dim: int = 8):
    idx = faiss.IndexFlatIP(dim)
    rng = np.random.default_rng(0)
    vecs = rng.random((n, dim)).astype("float32")
    idx.add(vecs)
    return idx, vecs


def test_sig_is_stable_and_content_sensitive(tmp_path):
    attacks = tmp_path / "attacks.jsonl"
    attacks.write_text('{"text":"a"}\n')

    s1 = l3_similarity._index_cache_sig(attacks)
    s2 = l3_similarity._index_cache_sig(attacks)
    assert s1 is not None and s1 == s2  # deterministic, no mtime dependence

    attacks.write_text('{"text":"a"}\n{"text":"b"}\n')  # DB change -> new sig
    assert l3_similarity._index_cache_sig(attacks) != s1


def test_sig_tracks_model_revision(tmp_path, monkeypatch):
    attacks = tmp_path / "attacks.jsonl"
    attacks.write_text('{"text":"a"}\n')
    before = l3_similarity._index_cache_sig(attacks)
    monkeypatch.setattr(l3_similarity, "_ONNX_MODEL_REVISION", "deadbeef" * 5)
    assert l3_similarity._index_cache_sig(attacks) != before


def test_sig_none_on_missing_input(tmp_path):
    assert l3_similarity._index_cache_sig(tmp_path / "nope.jsonl") is None


def test_roundtrip_save_load(tmp_cache):
    idx, vecs = _tiny_index()
    meta = [{"category": "jailbreak", "source": "x"}, {"category": "leak", "source": "y"}]
    l3_similarity._save_user_cache("sig123", idx, meta)

    loaded = l3_similarity._load_index("sig123", l3_similarity._USER_INDEX_PATH, l3_similarity._USER_META_PATH)
    assert loaded is not None
    loaded_idx, loaded_meta = loaded
    assert loaded_idx.ntotal == idx.ntotal
    assert loaded_meta == meta
    assert np.allclose(idx.search(vecs[:1], 1)[0], loaded_idx.search(vecs[:1], 1)[0])


def test_load_returns_none_on_sig_mismatch(tmp_cache):
    idx, _ = _tiny_index()
    l3_similarity._save_user_cache("sigA", idx, [])
    assert l3_similarity._load_index("sigB", l3_similarity._USER_INDEX_PATH, l3_similarity._USER_META_PATH) is None


def test_load_returns_none_when_absent(tmp_cache):
    assert l3_similarity._load_index("x", l3_similarity._USER_INDEX_PATH, l3_similarity._USER_META_PATH) is None


def test_save_is_best_effort(tmp_cache, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(faiss, "write_index", _boom)
    idx, _ = _tiny_index()
    l3_similarity._save_user_cache("sig", idx, [])  # must not raise
    assert not l3_similarity._USER_INDEX_PATH.exists()


def test_bundled_index_ships_and_matches_current_db():
    """The committed bundled index must match the current attack DB + pinned
    model revision. If this fails, run: python scripts/build_l3_index.py
    """
    if not l3_similarity._BUNDLED_INDEX_PATH.exists():
        pytest.skip("no bundled index committed")
    sig = l3_similarity._index_cache_sig(l3_similarity._DEFAULT_ATTACKS_PATH)
    assert sig is not None
    loaded = l3_similarity._load_index(sig, l3_similarity._BUNDLED_INDEX_PATH, l3_similarity._BUNDLED_META_PATH)
    assert loaded is not None, (
        "bundled index is stale vs the current attack DB / model revision — "
        "regenerate with `python scripts/build_l3_index.py` and commit."
    )
    index, metadata = loaded
    assert index.ntotal == len(metadata) > 0
