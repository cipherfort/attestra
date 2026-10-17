# SPDX-License-Identifier: Apache-2.0
"""SIEM sinks besides Sentinel (aap.plugins.interfaces.SiemSink). The events are the curated ones in
config/siem-events.yaml, already derived into the outbox; a sink only delivers them.

HttpSink    HTTPS POST. `json`: one JSON array per batch, `Authorization: Bearer <token>` (Elastic, Sumo Logic, a
            log shipper, a custom collector). `splunk_hec`: newline-delimited HEC events, `Authorization: Splunk
            <token>`, sourcetype `aap:security`.
SyslogSink  RFC 5424 messages over TLS with octet-counting framing (RFC 5425); facility authpriv; the event as JSON
            in MSG. The server certificate is verified (system CAs, or AAP_SIEM_SYSLOG_CA).

Delivery is at-least-once: a refused batch raises, the rows stay queued, and EventId lets the SIEM deduplicate.
"""

from __future__ import annotations

import json
import socket
import ssl
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import httpx

from aap.connectors.sentinel import SentinelError

SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "informational": 6, "info": 6}  # syslog severities
FACILITY_AUTHPRIV = 10


class SinkError(SentinelError):
    """Same failure contract as the Sentinel client: the dispatcher leaves the rows queued."""


def _time(row: dict[str, Any]) -> datetime:
    raw = str(row.get("TimeGenerated") or "")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)


class HttpSink:
    def __init__(self, url: str, token: str, fmt: str = "json", http: httpx.Client | None = None):
        if not url.startswith("https://"):
            raise SinkError("the SIEM URL must be https://")
        if fmt not in ("json", "splunk_hec"):
            raise SinkError("format must be json or splunk_hec")
        self.url, self.fmt, self._token = url, fmt, token
        self._http = http or httpx.Client(timeout=30.0, follow_redirects=False)

    def send(self, rows: Sequence[dict[str, Any]]) -> int:
        if not rows:
            return 0
        if self.fmt == "splunk_hec":
            body = "\n".join(
                json.dumps(
                    {"time": _time(r).timestamp(), "sourcetype": "aap:security", "source": "aap", "event": r},
                    default=str,
                )
                for r in rows
            )
            headers = {"Authorization": f"Splunk {self._token}", "Content-Type": "application/json"}
        else:
            body = json.dumps(list(rows), default=str)
            headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        try:
            r = self._http.post(self.url, content=body.encode(), headers=headers)
        except httpx.HTTPError as e:
            raise SinkError(f"SIEM endpoint unreachable: {type(e).__name__}") from e
        if r.status_code >= 300:
            raise SinkError(f"SIEM endpoint refused the batch: HTTP {r.status_code}")
        return len(rows)


def syslog_message(row: dict[str, Any], hostname: str) -> bytes:
    """RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG, framed for RFC 5425."""
    severity = SEVERITY.get(str(row.get("Severity", "")).lower(), 5)
    pri = FACILITY_AUTHPRIV * 8 + severity
    msgid = "".join(c for c in str(row.get("EventType", "-")) if 33 <= ord(c) <= 126)[:32] or "-"
    ts = _time(row).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    text = f"<{pri}>1 {ts} {hostname[:255] or '-'} aap - {msgid} - " + json.dumps(
        row, default=str, separators=(",", ":")
    )
    data = text.encode()
    return f"{len(data)} ".encode() + data


class SyslogSink:
    def __init__(self, address: str, ca_file: str | None = None, hostname: str | None = None, connect: Any = None):
        host, _, port = address.rpartition(":")
        if not host or not port.isdigit():
            raise SinkError("syslog address must be host:port (TLS, usually 6514)")
        self.host, self.port = host, int(port)
        self.hostname = hostname or socket.gethostname()
        self._ctx = ssl.create_default_context(cafile=ca_file)  # verifies the server certificate and hostname
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # RFC 9662: TLS 1.2 or later
        self._connect = connect or (lambda: socket.create_connection((self.host, self.port), timeout=15))

    def send(self, rows: Sequence[dict[str, Any]]) -> int:
        if not rows:
            return 0
        payload = b"".join(syslog_message(r, self.hostname) for r in rows)
        try:
            with self._connect() as raw, self._ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                tls.sendall(payload)
                tls.unwrap()  # close_notify (RFC 5425 section 4.4): an abrupt close can lose the buffered tail
        except (OSError, ssl.SSLError) as e:
            raise SinkError(f"syslog delivery failed: {type(e).__name__}") from e
        return len(rows)
