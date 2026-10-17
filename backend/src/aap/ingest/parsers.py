# SPDX-License-Identifier: Apache-2.0
"""Parsers for tool output carried in evidence bundles. Inputs are untrusted (threat T-05): size-limited upstream,
parsed with the standard JSON parser only, and every field read defensively.

In production DefectDojo's parsers normalise scanner output (ADR-001); these platform parsers cover the formats
the thin slice needs (SARIF 2.1.0, CycloneDX) and produce the summary contract the evaluators read.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aap.domain.sbom import assess_quality

MAX_JSON_BYTES = 100 * 1024 * 1024
MAX_UNZIPPED = 300 * 1024 * 1024
MAX_RATIO = 100
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


class BundleError(ValueError):
    pass


def safe_unzip(data: bytes, max_files: int = 60) -> dict[str, bytes]:
    """Zip-bomb and path-traversal safe extraction into memory."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise BundleError("artifact is not a zip archive") from e
    infos = zf.infolist()
    if len(infos) > max_files:
        raise BundleError(f"too many files ({len(infos)})")
    total = sum(i.file_size for i in infos)
    if total > MAX_UNZIPPED or (len(data) and total / len(data) > MAX_RATIO and total > 10 * 1024 * 1024):
        raise BundleError(f"decompressed size {total} exceeds limits")
    out: dict[str, bytes] = {}
    for info in infos:
        name = info.filename
        if info.is_dir():
            continue
        if name.startswith("/") or ".." in name.split("/") or "\\" in name:
            raise BundleError(f"unsafe path in archive: {name!r}")
        content = zf.read(info)
        if len(content) != info.file_size:
            raise BundleError("archive size mismatch")
        out[name] = content
    return out


def load_json(data: bytes) -> Any:
    if len(data) > MAX_JSON_BYTES:
        raise BundleError("JSON document too large")
    return json.loads(data)


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


@dataclass(frozen=True)
class SarifResult:
    rule_id: str
    message: str
    severity: str
    cwe: int | None
    uri: str
    line: int | None
    source_key: str  # stable identity inside the repo (partial fingerprint, else rule+location)


def parse_sarif(doc: Mapping[str, Any]) -> tuple[dict[str, Any], list[SarifResult]]:
    """Malformed structure is a BundleError (the bundle is rejected), never an unhandled exception (fuzzed)."""
    if not isinstance(doc, Mapping) or not str(doc.get("version", "")).startswith("2.1"):
        raise BundleError("unsupported SARIF version")
    try:
        return _parse_sarif(doc)
    except (AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError) as e:
        raise BundleError(f"malformed SARIF: {type(e).__name__}") from e


def _parse_sarif(doc: Mapping[str, Any]) -> tuple[dict[str, Any], list[SarifResult]]:
    results: list[SarifResult] = []
    tool, version = "?", ""
    for run in doc.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool, version = str(driver.get("name", tool)), str(driver.get("semanticVersion") or driver.get("version") or "")
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, Mapping)}
        for res in run.get("results") or []:
            rule_id = str(res.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            score = props.get("security-severity")
            level = str(res.get("level") or "warning")
            sev = (
                _severity_from_score(float(score))
                if score is not None
                else {"error": "high", "warning": "medium", "note": "low"}.get(level, "info")
            )
            cwe = None
            for tag in props.get("tags") or []:
                m = re.search(r"cwe[-/](\d+)", str(tag), re.I)
                if m:
                    cwe = int(m.group(1))
                    break
            loc = (res.get("locations") or [{}])[0].get("physicalLocation") or {}
            uri = str((loc.get("artifactLocation") or {}).get("uri") or "")
            line = (loc.get("region") or {}).get("startLine")
            fps = res.get("partialFingerprints") or {}
            key = str(
                fps.get("primaryLocationLineHash")
                or fps.get("primaryLocationStartColumnFingerprint")
                or f"{rule_id}:{uri}:{line}"
            )
            msg = str((res.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id)
            results.append(
                SarifResult(rule_id, msg[:500], sev, cwe, uri[:500], line if isinstance(line, int) else None, key)
            )
    counts = Counter(r.severity for r in results)
    worst = max((r.severity for r in results), key=SEVERITY_ORDER.index, default="info")
    summary = {
        "tool": tool,
        "tool_version": version,
        "results": len(results),
        "by_severity": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
        "max_severity": worst,
    }
    return summary, results


def sbom_summary(bom: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(bom, Mapping):
        raise BundleError("an SBOM must be a JSON object")
    try:
        count, pct, problems = assess_quality(bom)
    except (AttributeError, TypeError, ValueError, KeyError) as e:
        raise BundleError(f"malformed SBOM: {type(e).__name__}") from e
    return {
        "format": "cyclonedx",
        "spec_version": bom.get("specVersion"),
        "component_count": count,
        "purl_coverage_pct": pct,
        "quality_problems": problems,
    }


JUNIT_TAGS = ("asvs", "threat")


def parse_junit(data: bytes) -> dict[str, Any]:
    """JUnit XML → {tests, failures, skipped, asvs: {id: pass|fail}, threats: {id: pass|fail}}.

    Tests carry their links as properties: <property name="asvs" value="V6.2.1,V6.2.2"/>, <property name="threat"
    value="TM-07"/>. A requirement or threat is `fail` if any linked test failed or errored, `pass` if at least one
    linked test passed and none failed. Skipped tests verify nothing. DOCTYPE/ENTITY declarations are refused (XML
    entity expansion), so is anything over the bundle size limits enforced before parsing.
    """
    import xml.etree.ElementTree as ET  # DOCTYPE refused below; ElementTree resolves no external entities

    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise BundleError("JUnit XML with DOCTYPE/ENTITY declarations is refused")
    try:
        root = ET.fromstring(data)  # noqa: S314
    except ET.ParseError as e:
        raise BundleError(f"invalid JUnit XML: {e}") from e
    out: dict[str, Any] = {"tests": 0, "failures": 0, "skipped": 0, "asvs": {}, "threats": {}}
    for case in root.iter("testcase"):
        out["tests"] += 1
        failed = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        out["failures"] += int(failed)
        out["skipped"] += int(skipped)
        if skipped:
            continue
        for prop in case.iter("property"):
            name = (prop.get("name") or "").lower()
            if name not in JUNIT_TAGS:
                continue
            bucket = out["asvs" if name == "asvs" else "threats"]
            for ref in (prop.get("value") or "").replace(";", ",").split(","):
                ref = ref.strip()[:32]
                if ref:
                    bucket[ref] = "fail" if failed or bucket.get(ref) == "fail" else "pass"
    return out
