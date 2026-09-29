"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from python_env_repair.models import Platform
from tests.helpers import FakeEnv


@pytest.fixture
def fake_env(tmp_path: Path) -> FakeEnv:
    """A Linux-style fake environment whose interpreter is the test interpreter."""
    return FakeEnv(tmp_path)


@pytest.fixture
def windows_env(tmp_path: Path) -> FakeEnv:
    """A Windows-style fake environment, used for read-only detection logic only."""
    return FakeEnv(tmp_path, platform=Platform.WINDOWS, python=Path("C:/new/venv/Scripts/python.exe"))
