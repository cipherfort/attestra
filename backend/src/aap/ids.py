# SPDX-License-Identifier: Apache-2.0
"""Time-ordered UUIDv7 identifiers (RFC 9562), so primary keys sort by creation time (ADR-008)."""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76  # version 7
    value |= (rand >> 68 & 0xFFF) << 64  # rand_a (12 bits)
    value |= 0b10 << 62  # RFC 4122 variant
    value |= rand & ((1 << 62) - 1)  # rand_b (62 bits)
    return uuid.UUID(int=value)


def short_display(evidence_id: uuid.UUID | str) -> str:
    """Human-facing evidence reference, e.g. EV-3F2A9C1E."""
    return "EV-" + str(evidence_id).replace("-", "")[-8:].upper()
