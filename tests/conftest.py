"""Shared test fixtures for prompt-armor."""

from __future__ import annotations

import pytest

from prompt_armor.config import ShieldConfig


@pytest.fixture(scope="session")
def default_config() -> ShieldConfig:
    """Return the default configuration."""
    return ShieldConfig()
