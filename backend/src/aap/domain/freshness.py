# SPDX-License-Identifier: Apache-2.0
"""Evidence freshness per config/evidence-types.yaml (evidence model section 5).

Freshness is computed, never assumed: an evidence record is ACTIVE, EXPIRING, EXPIRED, SUPERSEDED or REVOKED
depending on its type's policy, the current time and what has happened since it was observed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from functools import lru_cache
from typing import Any


class EvidenceState(StrEnum):
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


USABLE = frozenset({EvidenceState.ACTIVE, EvidenceState.EXPIRING})


def parse_duration(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([hd])", str(text).strip())
    if not m:
        raise ValueError(f"bad duration {text!r} (expected e.g. 24h or 30d)")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(hours=n) if unit == "h" else timedelta(days=n)


@lru_cache(maxsize=512)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Git-style glob: `**/` = zero or more directories, `**` = anything, `*` and `?` stay inside a segment."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def path_matches(path: str, patterns: Iterable[str]) -> bool:
    return any(_glob_regex(p).match(path) for p in patterns)


@dataclass(frozen=True)
class FreshnessFacts:
    """What the engine knows about the world since the evidence was observed."""

    now: datetime
    # commit_bound: files changed on the default branch since the evidence commit (None = unknown / truncated)
    changed_paths: tuple[str, ...] | None = ()
    compare_truncated: bool = False
    # artifact_bound: is the evidence digest still a current or deployed one?
    digest_current: bool = True
    # continuous: when the authoritative source last confirmed this state
    last_confirmed: datetime | None = None
    # event_bound: invalidating events that occurred after the evidence (names from the policy)
    events_since: frozenset[str] = field(default_factory=frozenset)
    revoked: bool = False


@dataclass(frozen=True)
class FreshnessResult:
    state: EvidenceState
    valid_until: datetime | None
    reason: str


def evaluate(observed_at: datetime, policy: Mapping[str, Any], facts: FreshnessFacts) -> FreshnessResult:
    if facts.revoked:
        return FreshnessResult(EvidenceState.REVOKED, None, "revoked")
    kind = policy["policy"]
    warn = timedelta(days=int(policy.get("warn_days", 0)))
    ceiling = timedelta(days=int(policy["ceiling_days"])) if "ceiling_days" in policy else None

    if kind == "continuous":
        confirmed = facts.last_confirmed or observed_at
        until = confirmed + parse_duration(policy["ttl"])
        return _by_time(until, warn, facts.now, "not re-confirmed by the source within its TTL")

    if kind == "time_bound":
        until = observed_at + timedelta(days=int(policy["valid_days"]))
        return _by_time(until, warn, facts.now, "validity period ended")

    ceiling_at: datetime | None = observed_at + ceiling if ceiling else None
    if kind == "commit_bound":
        if facts.compare_truncated or facts.changed_paths is None:
            return FreshnessResult(EvidenceState.SUPERSEDED, ceiling_at, "change since evidence unknown (fail safe)")
        hits = [p for p in facts.changed_paths if path_matches(p, policy.get("paths", ["**"]))]
        if hits:
            shown = ", ".join(hits[:5]) + (" …" if len(hits) > 5 else "")
            return FreshnessResult(EvidenceState.SUPERSEDED, ceiling_at, f"meaningful change since evidence: {shown}")
    elif kind == "artifact_bound":
        if not facts.digest_current:
            reason = "artifact digest no longer current or deployed"
            return FreshnessResult(EvidenceState.SUPERSEDED, ceiling_at, reason)
    elif kind == "event_bound":
        fired = sorted(set(policy.get("invalidated_by", [])) & facts.events_since)
        if fired:
            return FreshnessResult(EvidenceState.SUPERSEDED, ceiling_at, f"invalidated by {', '.join(fired)}")
    else:
        raise ValueError(f"unknown freshness policy {kind!r}")

    if ceiling_at is None:
        return FreshnessResult(EvidenceState.ACTIVE, None, "current")
    return _by_time(ceiling_at, warn, facts.now, "ceiling reached without fresh evidence")


def _by_time(until: datetime, warn: timedelta, now: datetime, expired_reason: str) -> FreshnessResult:
    if now >= until:
        return FreshnessResult(EvidenceState.EXPIRED, until, expired_reason)
    if warn and now >= until - warn:
        return FreshnessResult(EvidenceState.EXPIRING, until, f"expires {until:%Y-%m-%d}")
    return FreshnessResult(EvidenceState.ACTIVE, until, "current")
