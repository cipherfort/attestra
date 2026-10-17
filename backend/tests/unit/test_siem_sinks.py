# SPDX-License-Identifier: Apache-2.0
"""SIEM sinks: HTTPS (JSON, Splunk HEC) against a mock transport; syslog over a real local TLS listener, including
refusing a server whose certificate it does not trust."""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aap.connectors.siem_sinks import HttpSink, SinkError, SyslogSink, syslog_message

ROW = {
    "TimeGenerated": "2026-10-16T09:00:00+00:00",
    "EventId": "e1",
    "EventType": "secret.exposed_active",
    "Severity": "high",
    "AppKey": "APP-00001",
}


def test_http_json_and_splunk_hec():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.headers["Authorization"], req.content.decode()))
        return httpx.Response(200)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    assert HttpSink("https://siem.test/ingest", "t0k", "json", http).send([ROW]) == 1
    assert seen[-1][0] == "Bearer t0k" and json.loads(seen[-1][1]) == [ROW]
    assert HttpSink("https://hec.test/services/collector", "t0k", "splunk_hec", http).send([ROW, ROW]) == 2
    auth, body = seen[-1]
    lines = [json.loads(line) for line in body.split("\n")]
    assert auth == "Splunk t0k" and len(lines) == 2 and lines[0]["sourcetype"] == "aap:security"
    assert (
        lines[0]["event"]["EventId"] == "e1"
        and lines[0]["time"] == dt.datetime(2026, 10, 16, 9, tzinfo=dt.UTC).timestamp()
    )


def test_http_refusals_keep_rows_queued_and_plain_http_is_refused():
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    with pytest.raises(SinkError, match="HTTP 403"):
        HttpSink("https://siem.test/ingest", "t", "json", http).send([ROW])
    with pytest.raises(SinkError, match="https"):
        HttpSink("http://siem.test/ingest", "t")


def test_syslog_message_is_rfc5424_and_octet_counted():
    framed = syslog_message(ROW, "aap-worker-1")
    length, _, msg = framed.partition(b" ")
    assert int(length) == len(msg)
    assert msg.startswith(
        b"<83>1 2026-10-16T09:00:00.000000Z aap-worker-1 aap - secret.exposed_active - {"
    )  # authpriv.err
    assert json.loads(msg.split(b" - ", 2)[2])["EventId"] == "e1"


def _cert(tmp_path, cn="localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / f"{cn}.pem", tmp_path / f"{cn}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


def _server(cert_path, key_path, received):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)
    sock = socket.create_server(("127.0.0.1", 0))

    def serve():
        try:
            conn, _ = sock.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                data = b""
                while chunk := tls.recv(65536):
                    data += chunk
                tls.unwrap()
                received.append(data)
        except (ssl.SSLError, OSError):
            received.append(None)
        finally:
            sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_syslog_over_tls_to_a_trusted_server(tmp_path):
    cert, key = _cert(tmp_path)
    received: list = []
    port = _server(cert, key, received)
    sink = SyslogSink(f"localhost:{port}", ca_file=str(cert), hostname="aap-test")
    assert sink.send([ROW, {**ROW, "EventId": "e2"}]) == 2
    for _ in range(50):
        if received:
            break
        threading.Event().wait(0.05)
    data = received[0]
    first_len = int(data.split(b" ", 1)[0])
    assert b'"EventId":"e1"' in data and b'"EventId":"e2"' in data and len(data) > first_len


def test_syslog_refuses_an_untrusted_server(tmp_path):
    cert, key = _cert(tmp_path)
    other, _ = _cert(tmp_path, "other-ca")
    received: list = []
    port = _server(cert, key, received)
    with pytest.raises(SinkError, match="syslog delivery failed"):
        SyslogSink(f"localhost:{port}", ca_file=str(other)).send([ROW])


def test_only_one_sink_may_take_the_events(monkeypatch):
    from aap.worker import connectors

    monkeypatch.setenv("AAP_SIEM_SYSLOG", "siem.example.org:6514")
    monkeypatch.setenv("AAP_SENTINEL_DCE", "https://dce.example.org")
    monkeypatch.setenv("AAP_SENTINEL_DCR_ID", "dcr-immutable-id")  # a fully configured second sink
    out = connectors.syslog(None, None, None, {})  # refused before any database or network access
    assert out.items == 0 and "more than one SIEM sink" in out.errors[0]
