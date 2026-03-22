"""Analytics collector — persists analysis results to SQLite.

Records every analyze() call to a local SQLite database for the
analytics dashboard. Non-blocking: writes happen in a background thread.

Usage:
    collector = AnalyticsCollector(db_path, store_prompts=False)
    collector.record(text, result)
    collector.close()
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from pathlib import Path
from queue import Empty, Queue

from prompt_armor.models import ShieldResult

logger = logging.getLogger("prompt_armor")

_DEFAULT_DB_PATH = Path.home() / ".prompt-armor" / "analytics.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    prompt_hash TEXT NOT NULL,
    prompt_text TEXT,
    prompt_length INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    confidence REAL NOT NULL,
    decision TEXT NOT NULL,
    categories TEXT NOT NULL,
    evidence TEXT NOT NULL,
    layer_scores TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    needs_council INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_timestamp ON analyses(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_decision ON analyses(decision);",
    "CREATE INDEX IF NOT EXISTS idx_risk_score ON analyses(risk_score);",
]

_INSERT = """
INSERT INTO analyses (
    prompt_hash, prompt_text, prompt_length,
    risk_score, confidence, decision,
    categories, evidence, layer_scores,
    latency_ms, needs_council,
    lite_decision,
    council_decision, council_reasoning, council_confidence,
    council_model, council_latency_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_MIGRATE_COUNCIL = [
    "ALTER TABLE analyses ADD COLUMN lite_decision TEXT;",
    "ALTER TABLE analyses ADD COLUMN council_decision TEXT;",
    "ALTER TABLE analyses ADD COLUMN council_reasoning TEXT;",
    "ALTER TABLE analyses ADD COLUMN council_confidence TEXT;",
    "ALTER TABLE analyses ADD COLUMN council_model TEXT;",
    "ALTER TABLE analyses ADD COLUMN council_latency_ms REAL DEFAULT 0;",
]

_CLEANUP = """
DELETE FROM analyses WHERE id NOT IN (
    SELECT id FROM analyses ORDER BY id DESC LIMIT ?
);
"""


class AnalyticsCollector:
    """Non-blocking analytics collector backed by SQLite."""

    def __init__(
        self,
        db_path: Path | None = None,
        store_prompts: bool = False,
        max_records: int = 100_000,
    ) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._store_prompts = store_prompts
        self._max_records = max_records
        self._queue: Queue[tuple[str, ShieldResult] | None] = Queue(maxsize=10_000)
        self._thread: threading.Thread | None = None
        self._running = False

        # Ensure directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize schema
        self._init_db()

        # Start background writer
        self._start_writer()

    def _init_db(self) -> None:
        """Create tables and indexes if they don't exist."""
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute(_CREATE_TABLE)
        for idx in _CREATE_INDEXES:
            conn.execute(idx)
        # Migrate: add council columns if missing (idempotent)
        for stmt in _MIGRATE_COUNCIL:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # Column already exists
        conn.commit()
        conn.close()

    def _start_writer(self) -> None:
        """Start the background writer thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="prompt-armor-collector"
        )
        self._thread.start()

    def _writer_loop(self) -> None:
        """Background loop that drains the queue and writes to SQLite."""
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")

        batch_count = 0
        batch_size = 100  # Commit every N records for performance

        while self._running:
            try:
                item = self._queue.get(timeout=1.0)
            except Empty:
                # Commit any pending writes on idle
                if batch_count % batch_size != 0 and batch_count > 0:
                    conn.commit()
                continue

            if item is None:
                conn.commit()  # Flush remaining
                break

            text, result = item

            try:
                prompt_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
                prompt_text = text if self._store_prompts else None
                categories = json.dumps([c.value for c in result.categories])
                evidence = json.dumps([
                    {
                        "layer": e.layer,
                        "category": e.category.value,
                        "description": e.description,
                        "score": e.score,
                    }
                    for e in result.evidence
                ])
                layer_scores = json.dumps({
                    lr.layer: lr.score for lr in result.layer_results
                })

                conn.execute(_INSERT, (
                    prompt_hash,
                    prompt_text,
                    len(text),
                    result.risk_score,
                    result.confidence,
                    result.decision.value,
                    categories,
                    evidence,
                    layer_scores,
                    result.latency_ms,
                    int(result.needs_council),
                    result.lite_decision,
                    result.council_decision,
                    result.council_reasoning,
                    result.council_confidence,
                    result.council_model,
                    result.council_latency_ms,
                ))

                batch_count += 1

                # Batch commit for performance (every batch_size records)
                if batch_count % batch_size == 0:
                    conn.commit()

                # Periodic cleanup
                if batch_count % 1000 == 0 and self._max_records > 0:
                    conn.execute(_CLEANUP, (self._max_records,))
                    conn.commit()

            except Exception as e:
                logger.warning("Analytics write failed: %s", e)

        conn.close()

    def record(self, text: str, result: ShieldResult) -> None:
        """Queue a result for background writing. Non-blocking."""
        try:
            self._queue.put_nowait((text, result))
        except Exception:
            pass  # Drop silently if queue is full

    def close(self) -> None:
        """Stop the background writer."""
        self._running = False
        try:
            self._queue.put_nowait(None)
        except Exception:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    @property
    def db_path(self) -> Path:
        """Return the database file path."""
        return self._db_path
