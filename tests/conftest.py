"""Shared test fixtures for llm-shield."""

from __future__ import annotations

import pytest

from llm_shield.config import ShieldConfig


@pytest.fixture(scope="session")
def default_config() -> ShieldConfig:
    """Return the default configuration."""
    return ShieldConfig()
