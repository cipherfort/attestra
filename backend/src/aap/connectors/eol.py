# SPDX-License-Identifier: Apache-2.0
"""endoflife.date: release cycles and their end-of-life dates (public API, no account). Mirror: AAP_EOL_API."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

import httpx

from aap.connectors.vuln_feeds import FeedError

EOL_API = "https://endoflife.date/api"
PRODUCT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class Cycle:
    cycle: str
    eol: date | None  # None: not end of life (or no date published)
    eol_now: bool  # the API says `eol: true` without a date


class EolClient:
    def __init__(self, http: httpx.Client | None = None, base_url: str | None = None):
        self.http = http or httpx.Client(timeout=30.0, follow_redirects=False, headers={"User-Agent": "aap-eol"})
        self.base = (base_url or os.environ.get("AAP_EOL_API") or EOL_API).rstrip("/")

    def cycles(self, product: str) -> list[Cycle]:
        if not PRODUCT.match(product):
            raise FeedError(f"invalid product name {product!r}")
        r = self.http.get(f"{self.base}/{product}.json")
        if r.status_code != 200:
            raise FeedError(f"endoflife.date {product}: HTTP {r.status_code}")
        out = []
        for row in r.json():
            eol: Any = row.get("eol")
            when = date.fromisoformat(eol) if isinstance(eol, str) else None
            out.append(Cycle(str(row["cycle"]), when, eol is True))
        return out


def match_cycle(version: str, cycles: list[Cycle]) -> Cycle | None:
    """The most specific cycle the version belongs to: 3.2.5 → '3.2.5', '3.2', then '3'."""
    by_name = {c.cycle: c for c in cycles}
    parts = re.split(r"[.+-]", version.lstrip("v"))
    for n in range(len(parts), 0, -1):
        c = by_name.get(".".join(parts[:n]))
        if c is not None:
            return c
    return None
