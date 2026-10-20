# SPDX-License-Identifier: Apache-2.0
"""SBOM quality assessment (SBOM Standard SBM-04): pure, no I/O."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any

NTIA_FIELDS = ("name", "version")
# CycloneDX component types that are not packages: SBOM generators (Syft, for one) also list the files they read,
# such as a lockfile or a workflow file. Those have no purl or version and are not part of the inventory.
NOT_PACKAGES = frozenset({"file", "data"})


def walk_components(components: Sequence[Mapping[str, Any]]) -> Iterator[Mapping[str, Any]]:
    for c in components:
        yield c
        yield from walk_components(c.get("components") or [])


def assess_quality(bom: Mapping[str, Any], min_purl_pct: float = 95.0) -> tuple[int, float, list[str]]:
    """Returns (component count, purl coverage %, problems). Any problem makes the SBOM inconclusive."""
    comps = [c for c in walk_components(bom.get("components") or []) if c.get("type") not in NOT_PACKAGES]
    problems = []
    if bom.get("bomFormat") != "CycloneDX":
        problems.append("not a CycloneDX document")
    if not comps:
        problems.append("no components")
    with_purl = sum(1 for c in comps if c.get("purl"))
    pct = round(100.0 * with_purl / len(comps), 1) if comps else 0.0
    if comps and pct < min_purl_pct:
        problems.append(f"purl coverage {pct}% < {min_purl_pct}%")
    missing = sum(1 for c in comps if not all(c.get(f) for f in NTIA_FIELDS))
    if missing:
        problems.append(f"{missing} components missing name/version")
    return len(comps), pct, problems
