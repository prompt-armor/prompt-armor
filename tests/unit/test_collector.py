"""Tests for collector.py — SQLite analytics writer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from prompt_armor.collector import AnalyticsCollector
from prompt_armor.models import Category, Decision, Evidence, ShieldResult


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_analytics.db"


@pytest.fixture
def collector(tmp_db: Path) -> AnalyticsCollector:
    c = AnalyticsCollector(db_path=tmp_db, store_prompts=True, max_records=1000)
    yield c
    c.close()


def _make_result(**kwargs: object) -> ShieldResult:
    defaults = {
        "risk_score": 0.5,
        "confidence": 0.8,
        "decision": Decision.WARN,
        "categories": (Category.PROMPT_INJECTION,),
        "evidence": (
            Evidence(
                layer="l1_regex",
                category=Category.PROMPT_INJECTION,
                description="test",
                score=0.5,
            ),
        ),
    }
    defaults.update(kwargs)
    return ShieldResult(**defaults)  # type: ignore[arg-type]


class TestCollectorWrite:
    """Test that records are written to SQLite."""

    def test_write_single(self, collector: AnalyticsCollector, tmp_db: Path) -> None:
        result = _make_result()
        collector.record("test prompt", result)
        collector.flush()
        conn = sqlite3.connect(str(tmp_db))
        count = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        conn.close()
        assert count == 1

    def test_write_multiple(self, collector: AnalyticsCollector, tmp_db: Path) -> None:
        for i in range(5):
            collector.record(f"prompt {i}", _make_result(risk_score=i * 0.2))
        collector.flush()
        conn = sqlite3.connect(str(tmp_db))
        count = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        conn.close()
        assert count == 5

    def test_stores_prompt_text(self, collector: AnalyticsCollector, tmp_db: Path) -> None:
        collector.record("hello world", _make_result())
        collector.flush()
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT prompt_text FROM analyses LIMIT 1").fetchone()
        conn.close()
        assert row[0] == "hello world"

    def test_no_prompt_when_disabled(self, tmp_path: Path) -> None:
        db = tmp_path / "no_prompt.db"
        c = AnalyticsCollector(db_path=db, store_prompts=False)
        c.record("secret text", _make_result())
        c.flush()
        conn = sqlite3.connect(str(db))
        row = conn.execute("SELECT prompt_text FROM analyses LIMIT 1").fetchone()
        conn.close()
        c.close()
        assert row[0] is None

    def test_decision_stored(self, collector: AnalyticsCollector, tmp_db: Path) -> None:
        collector.record("test", _make_result(decision=Decision.BLOCK))
        collector.flush()
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT decision FROM analyses LIMIT 1").fetchone()
        conn.close()
        assert row[0] == "block"


class TestCollectorSchema:
    """Test schema creation and migration."""

    def test_creates_table(self, tmp_db: Path) -> None:
        c = AnalyticsCollector(db_path=tmp_db)
        conn = sqlite3.connect(str(tmp_db))
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        conn.close()
        c.close()
        assert ("analyses",) in tables

    def test_council_columns_exist(self, tmp_db: Path) -> None:
        c = AnalyticsCollector(db_path=tmp_db)
        conn = sqlite3.connect(str(tmp_db))
        cols = [row[1] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()]
        conn.close()
        c.close()
        assert "council_decision" in cols
        assert "council_reasoning" in cols
        assert "lite_decision" in cols

    def test_idempotent_migration(self, tmp_db: Path) -> None:
        # Create twice — should not error
        c1 = AnalyticsCollector(db_path=tmp_db)
        c1.close()
        c2 = AnalyticsCollector(db_path=tmp_db)
        c2.close()


class TestCollectorCouncilFields:
    """Test that council data is persisted."""

    def test_council_fields_stored(self, collector: AnalyticsCollector, tmp_db: Path) -> None:
        result = _make_result(
            council_decision="MALICIOUS",
            council_reasoning="attack detected",
            council_confidence="HIGH",
            council_model="phi3:mini",
            council_latency_ms=1500.0,
            lite_decision="warn",
        )
        collector.record("test", result)
        collector.flush()
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute(
            "SELECT council_decision, council_reasoning, council_model, lite_decision FROM analyses LIMIT 1"
        ).fetchone()
        conn.close()
        assert row[0] == "MALICIOUS"
        assert row[1] == "attack detected"
        assert row[2] == "phi3:mini"
        assert row[3] == "warn"
