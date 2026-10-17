# SPDX-License-Identifier: Apache-2.0
"""Public vulnerability intelligence, no account needed: OSV (advisories matched by package URL), CISA KEV (known
exploited) and FIRST EPSS (exploit likelihood). Read-only HTTPS GETs/POSTs; no credentials; nothing about the
organization is sent except package URLs (OSV) and CVE ids (EPSS).

Mirrors (air-gapped or egress-restricted deployments): AAP_OSV_API, AAP_KEV_URL, AAP_EPSS_API.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any

import httpx

OSV_API = "https://api.osv.dev"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
OSV_BATCH = 1000  # querybatch limit
EPSS_BATCH = 100
KEV_MIN_ENTRIES = 1000  # the catalogue has >1,400 entries; fewer means a truncated or wrong download
MAX_PAGES = 20


class FeedError(RuntimeError):
    pass


def _client(http: httpx.Client | None) -> httpx.Client:
    return http or httpx.Client(timeout=60.0, follow_redirects=False, headers={"User-Agent": "aap-vuln-feeds"})


def _check(r: httpx.Response, what: str) -> Any:
    if r.status_code != 200:
        raise FeedError(f"{what}: HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as e:
        raise FeedError(f"{what}: not JSON") from e


class OsvClient:
    def __init__(self, http: httpx.Client | None = None, base_url: str | None = None):
        self.http = _client(http)
        self.base = (base_url or os.environ.get("AAP_OSV_API") or OSV_API).rstrip("/")

    def querybatch(self, purls: Sequence[str]) -> dict[str, dict[str, str]]:
        """purl (with version) → {vuln id: modified}. Follows next_page_token for packages with many advisories."""
        out: dict[str, dict[str, str]] = {p: {} for p in purls}
        for start in range(0, len(purls), OSV_BATCH):
            pending = [(p, None) for p in purls[start : start + OSV_BATCH]]
            for _ in range(MAX_PAGES):
                if not pending:
                    break
                queries = [{"package": {"purl": p}, **({"page_token": t} if t else {})} for p, t in pending]
                body = _check(self.http.post(f"{self.base}/v1/querybatch", json={"queries": queries}), "OSV querybatch")
                results = body.get("results") or []
                if len(results) != len(pending):
                    raise FeedError("OSV querybatch: result count differs from query count")
                nxt = []
                for (purl, _), res in zip(pending, results, strict=True):
                    for v in res.get("vulns") or []:
                        out[purl][v["id"]] = v.get("modified", "")
                    if res.get("next_page_token"):
                        nxt.append((purl, res["next_page_token"]))
                pending = nxt
            else:
                raise FeedError("OSV querybatch: too many result pages")
        return out

    def vuln(self, vuln_id: str) -> dict[str, Any]:
        return dict(_check(self.http.get(f"{self.base}/v1/vulns/{vuln_id}"), f"OSV {vuln_id}"))


@dataclass(frozen=True)
class KevEntry:
    cve: str
    added: date
    ransomware: bool


class KevClient:
    def __init__(self, http: httpx.Client | None = None, url: str | None = None):
        self.http = _client(http)
        self.url = url or os.environ.get("AAP_KEV_URL") or KEV_URL

    def catalogue(self) -> tuple[str, list[KevEntry]]:
        body = _check(self.http.get(self.url), "CISA KEV")
        vulns = body.get("vulnerabilities") or []
        if len(vulns) < KEV_MIN_ENTRIES or (body.get("count") is not None and int(body["count"]) != len(vulns)):
            # never clear "known exploited" flags from a partial download (fail closed)
            raise FeedError(f"CISA KEV: implausible catalogue ({len(vulns)} entries, count {body.get('count')})")
        return str(body.get("catalogVersion", "")), [
            KevEntry(v["cveID"], date.fromisoformat(v["dateAdded"]), v.get("knownRansomwareCampaignUse") == "Known")
            for v in vulns
        ]


@dataclass(frozen=True)
class EpssScore:
    cve: str
    epss: Decimal
    percentile: Decimal
    day: date


class EpssClient:
    def __init__(self, http: httpx.Client | None = None, base_url: str | None = None):
        self.http = _client(http)
        self.base = base_url or os.environ.get("AAP_EPSS_API") or EPSS_API

    def scores(self, cves: Iterable[str]) -> list[EpssScore]:
        cves = sorted(set(cves))
        out = []
        for start in range(0, len(cves), EPSS_BATCH):
            batch = cves[start : start + EPSS_BATCH]
            body = _check(self.http.get(self.base, params={"cve": ",".join(batch)}), "FIRST EPSS")
            for row in body.get("data") or []:
                out.append(
                    EpssScore(
                        row["cve"],
                        Decimal(str(row["epss"])),
                        Decimal(str(row["percentile"])),
                        date.fromisoformat(row["date"]),
                    )
                )
        return out
