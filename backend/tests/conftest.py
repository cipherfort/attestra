# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aap.config import ConfigBundle

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def bundle() -> ConfigBundle:
    return ConfigBundle.load()


@pytest.fixture
def now() -> datetime:
    return NOW
