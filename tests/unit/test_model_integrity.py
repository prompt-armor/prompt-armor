"""Supply-chain integrity checks for auto-downloaded model artifacts.

L5 loads a joblib/pickle (code-executing) artifact and L3 an ONNX graph, both
fetched from HuggingFace. These tests pin the behavior that prevents a
compromised/tampered artifact from being loaded: a pinned revision on every
download, plus a sha256 verification before the L5 pickle is deserialized
(joblib.load runs arbitrary code, so an unverified pickle is an RCE vector).
"""

from __future__ import annotations

import hashlib

import pytest

from prompt_armor.layers import l3_similarity, l5_negative_selection


def test_l5_pins_revision_and_hash():
    rev = l5_negative_selection._MODEL_REVISION
    digest = l5_negative_selection._MODEL_SHA256
    assert len(rev) == 40 and int(rev, 16) >= 0  # 40-hex git commit sha
    assert len(digest) == 64 and int(digest, 16) >= 0  # 64-hex sha256


def test_l3_pins_revision():
    rev = l3_similarity._ONNX_MODEL_REVISION
    assert len(rev) == 40 and int(rev, 16) >= 0


def test_sha256_helper_matches_known_value(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"hello world")
    assert l5_negative_selection._sha256(p) == hashlib.sha256(b"hello world").hexdigest()


def test_l5_refuses_tampered_pickle(tmp_path, monkeypatch):
    """A pickle whose content hash != the pin must be rejected, not loaded."""
    fake = tmp_path / "l5_negative_selection.pkl"
    # Content that does NOT match _MODEL_SHA256 — stand-in for a malicious pickle.
    fake.write_bytes(b"pwned: arbitrary pickle payload")
    monkeypatch.setattr(l5_negative_selection, "_MODEL_PATH", fake)

    layer = l5_negative_selection.L5NegativeSelectionLayer()
    with pytest.raises(ValueError, match="integrity check failed"):
        layer.setup()


def test_l5_accepts_matching_hash(tmp_path, monkeypatch):
    """If the content matches the pinned hash, setup proceeds past the check.

    We point the hash constant at a tiny file's digest so the integrity gate
    passes without needing the real 3MB model; joblib.load then fails on the
    non-model bytes — proving the hash gate ran BEFORE deserialization.
    """
    blob = tmp_path / "l5_negative_selection.pkl"
    blob.write_bytes(b"not-a-real-model-but-hash-matches")
    monkeypatch.setattr(l5_negative_selection, "_MODEL_PATH", blob)
    monkeypatch.setattr(l5_negative_selection, "_MODEL_SHA256", l5_negative_selection._sha256(blob))

    pytest.importorskip("joblib")
    layer = l5_negative_selection.L5NegativeSelectionLayer()
    # Passes the integrity gate, then fails to deserialize the fake bytes —
    # the failure must NOT be our integrity error (proving the gate let it through).
    with pytest.raises(Exception) as exc:
        layer.setup()
    assert "integrity check failed" not in str(exc.value)
