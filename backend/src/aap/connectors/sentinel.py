# SPDX-License-Identifier: Apache-2.0
"""Microsoft Sentinel via the Azure Monitor Logs Ingestion API (ADR-020).

Infra (examples/terraform/azure/modules/sentinel) creates the Log Analytics workspace with Sentinel, the custom table
`AppSecPlatform_CL`, a data collection endpoint (DCE) and rule (DCR) whose stream `Custom-AppSecPlatform` has exactly
`STREAM_COLUMNS`, and grants the platform identity "Monitoring Metrics Publisher" on the DCR only.

POST {dce}/dataCollectionRules/{dcr_immutable_id}/streams/{stream}?api-version=2023-01-01, JSON array ≤ 1 MB,
bearer token for https://monitor.azure.com/.default → 204.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Sequence
from typing import Any

import httpx

MONITOR_SCOPE = "https://monitor.azure.com/.default"
STREAM = "Custom-AppSecPlatform"
MAX_BODY = 900 * 1024  # stay under the 1 MB request limit after JSON encoding
# Column name → Log Analytics type. Terraform's stream declaration is generated from the same list (tested).
STREAM_COLUMNS: dict[str, str] = {
    "TimeGenerated": "datetime",
    "EventId": "string",
    "EventType": "string",
    "Severity": "string",
    "AppKey": "string",
    "AppTier": "int",
    "Repo": "string",
    "ResourceIds": "dynamic",
    "VulnIds": "dynamic",
    "Actor": "string",
    "PlatformUrl": "string",
    "CorrelationId": "string",
    "Details": "dynamic",
}


class SentinelError(Exception):
    pass


class LogsIngestionClient:
    def __init__(
        self,
        endpoint: str,
        dcr_immutable_id: str,
        token: Callable[[], str],
        stream: str = STREAM,
        http: httpx.Client | None = None,
    ):
        if not endpoint.startswith("https://"):
            raise SentinelError("the data collection endpoint must be https")
        self.url = (
            f"{endpoint.rstrip('/')}/dataCollectionRules/{dcr_immutable_id}/streams/{stream}?api-version=2023-01-01"
        )
        self._token = token
        self._http = http or httpx.Client(timeout=30.0, follow_redirects=False)

    def send(self, rows: Sequence[dict[str, Any]]) -> int:
        """Send rows in ≤ 1 MB gzip batches; returns rows accepted. Raises on the first refused batch."""
        sent, size = 0, 2
        batch: list[dict[str, Any]] = []
        for row in rows:
            unknown = set(row) - set(STREAM_COLUMNS)
            if unknown:
                raise SentinelError(f"columns not in the DCR stream: {sorted(unknown)}")
            n = len(json.dumps(row, default=str)) + 1
            if batch and size + n > MAX_BODY:
                sent += self._post(batch)
                batch, size = [], 2
            batch.append(row)
            size += n
        if batch:
            sent += self._post(batch)
        return sent

    def _post(self, batch: list[dict[str, Any]]) -> int:
        body = gzip.compress(json.dumps(batch, default=str).encode())
        r = self._http.post(
            self.url,
            content=body,
            headers={
                "Authorization": f"Bearer {self._token()}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        if r.status_code != 204:
            raise SentinelError(f"Logs Ingestion refused a batch ({r.status_code}): {r.text[:200]}")
        return len(batch)


class LogAnalyticsQuery:
    """Read-only KQL for log-source health (Log Analytics Reader on the workspace)."""

    def __init__(self, workspace_id: str, token: Callable[[], str], http: httpx.Client | None = None):
        self.url = f"https://api.loganalytics.azure.com/v1/workspaces/{workspace_id}/query"
        self._token = token
        self._http = http or httpx.Client(timeout=60.0, follow_redirects=False)

    def scalar(self, kql: str, timespan: str = "P1D") -> int:
        r = self._http.post(
            self.url, json={"query": kql, "timespan": timespan}, headers={"Authorization": f"Bearer {self._token()}"}
        )
        if r.status_code != 200:
            raise SentinelError(f"query refused ({r.status_code})")
        rows = r.json()["tables"][0]["rows"]
        return int(rows[0][0]) if rows else 0


def monitor_token(credential: Any) -> Callable[[], str]:
    return lambda: str(credential.get_token(MONITOR_SCOPE).token)


def log_analytics_token(credential: Any) -> Callable[[], str]:
    return lambda: str(credential.get_token("https://api.loganalytics.io/.default").token)
