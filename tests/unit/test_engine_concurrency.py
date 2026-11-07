"""Concurrent analyze() calls must not skip layers because of time spent queued.

The engine's per-layer timeout used to start when a layer was submitted to the
shared pool. With many callers on one engine (an agent framework checking tool
outputs with 12 concurrent connections), layers waited in the queue past the
budget and were skipped fail-open: a downstream study logged 12,784 skipped
L2/L4 runs, measuring a weaker detector than the one it named.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from prompt_armor import engine as engine_mod
from prompt_armor.layers.base import BaseLayer
from prompt_armor.models import LayerResult


class _SlowLayer(BaseLayer):
    def __init__(self, name: str, seconds: float) -> None:
        self.name = name
        self._seconds = seconds

    def setup(self) -> None:
        pass

    def analyze(self, text: str) -> LayerResult:
        time.sleep(self._seconds)
        return LayerResult(layer=self.name, score=0.0, confidence=1.0)


@pytest.fixture
def slow_engine(monkeypatch):
    layers = [_SlowLayer("a", 0.3), _SlowLayer("b", 0.3)]
    monkeypatch.setattr(engine_mod, "_build_layers", lambda config: layers)
    monkeypatch.setattr(engine_mod, "_LAYER_TIMEOUT_S", 1.0)
    eng = engine_mod.LiteEngine()
    # One worker: every concurrent call queues behind the others' layers.
    eng._pool.shutdown(wait=False)
    eng._pool = ThreadPoolExecutor(max_workers=1)
    yield eng
    eng.close()


def test_queued_layers_are_not_skipped(slow_engine, caplog):
    results = []

    def call() -> None:
        results.append(slow_engine.analyze("hello"))

    threads = [threading.Thread(target=call) for _ in range(6)]
    with caplog.at_level(logging.WARNING, logger="prompt_armor"):
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    # 6 calls x 2 layers x 0.3s on one worker: the last ones queue ~3.3s, past the 1s budget.
    assert "skipping" not in caplog.text
    assert all({lr.layer for lr in r.layer_results} == {"a", "b"} for r in results)
    assert slow_engine.skipped_layers == {}


def test_a_layer_slower_than_its_budget_is_still_skipped(monkeypatch, caplog):
    monkeypatch.setattr(engine_mod, "_build_layers", lambda config: [_SlowLayer("slow", 0.5)])
    monkeypatch.setattr(engine_mod, "_LAYER_TIMEOUT_S", 0.1)
    eng = engine_mod.LiteEngine()
    try:
        with caplog.at_level(logging.WARNING, logger="prompt_armor"):
            result = eng.analyze("hello")
        skipped = eng.skipped_layers
    finally:
        eng.close()
    assert "Layer slow timed out, skipping" in caplog.text
    assert result.layer_results == ()
    # Counted, so the benchmark and the fusion training dump can refuse the run.
    assert skipped == {"slow": 1}


class _CrashingLayer(_SlowLayer):
    def analyze(self, text: str) -> LayerResult:
        raise RuntimeError("boom")


def test_crashed_layers_are_counted_as_skipped(monkeypatch):
    layers = [_SlowLayer("ok", 0.0), _CrashingLayer("bad", 0.0)]
    monkeypatch.setattr(engine_mod, "_build_layers", lambda config: layers)
    eng = engine_mod.LiteEngine()
    try:
        eng.analyze("hello")
        eng.analyze("world")
        skipped = eng.skipped_layers
    finally:
        eng.close()
    assert skipped == {"bad": 2}
