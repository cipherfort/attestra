# SPDX-License-Identifier: Apache-2.0
"""Deterministic finding identities (data model §4): the same real issue maps to the same finding on every run."""

from __future__ import annotations

import hashlib
import re

_VULN_PRIORITY = (re.compile(r"^CVE-\d{4}-\d+$"), re.compile(r"^GHSA-"), re.compile(r".*"))


def _h(*parts: object) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def canonical_vuln_id(ids: list[str] | tuple[str, ...]) -> str:
    """Alias resolution: CVE > GHSA > anything else (OSV, MAL); ties broken lexically for stability."""
    if not ids:
        raise ValueError("no vulnerability ids")
    for pattern in _VULN_PRIORITY:
        hits = sorted(i for i in ids if pattern.match(i))
        if hits:
            return hits[0]
    raise AssertionError("unreachable")


def purl_without_version(purl: str) -> str:
    base = purl.split("?", 1)[0].split("#", 1)[0]
    name, sep, _version = base.rpartition("@")
    return name if sep and "/" in name else base


def dependency(scope_ref: str, purl: str, vuln_ids: list[str]) -> str:
    return "dep:" + _h("dep", scope_ref, purl_without_version(purl), canonical_vuln_id(vuln_ids))


def code(repo_id: int, tool: str, rule_id: str, source_key: str) -> str:
    return "code:" + _h("code", repo_id, tool, rule_id, source_key)


def secret(repo_id: int, secret_type: str, alert_number: int) -> str:
    return "secret:" + _h("secret", repo_id, secret_type, alert_number)


def iac(repo_id: int, policy_id: str, resource: str) -> str:
    return "iac:" + _h("iac", repo_id, policy_id, resource)


def container(image_name: str, purl: str, vuln_ids: list[str]) -> str:
    return "ctr:" + _h("ctr", image_name, purl_without_version(purl), canonical_vuln_id(vuln_ids))


def cloud(provider: str, resource_id: str, rule_id: str) -> str:
    return "cloud:" + _h("cloud", provider, resource_id.lower(), rule_id)


def exception_expired(exception_key: str) -> str:
    return _h("exception_expired", exception_key)


def control_gap(application_id: str, control_key: str, scope_ref: str) -> str:
    return "gap:" + _h("gap", application_id, control_key, scope_ref)


def ticket_dedup_key(application_id: str, repository: str, finding_type: str, fix_unit: str) -> str:
    """ADR-018: dependency/container findings group by the component a single upgrade fixes."""
    return f"{finding_type}|{application_id}|{repository}|{fix_unit}"
