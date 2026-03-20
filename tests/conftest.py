"""Shared test fixtures for prompt-shield."""

from __future__ import annotations

import pytest

from prompt_shield.config import ShieldConfig


@pytest.fixture(scope="session")
def default_config() -> ShieldConfig:
    """Return the default configuration."""
    return ShieldConfig()
