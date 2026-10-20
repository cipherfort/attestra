# SPDX-License-Identifier: Apache-2.0
"""SBOM quality (SBOM standard SBM-04): measured over the packages, not over the files a generator also lists."""

from __future__ import annotations

import json
from pathlib import Path

from aap.domain.sbom import assess_quality

REAL = json.loads((Path(__file__).parent.parent / "fixtures" / "sbom" / "syft-fortproof-e2e.cdx.json").read_text())


def test_a_real_syft_sbom_with_file_components_is_conclusive():
    """Syft lists requirements.txt and the workflow file as `file` components (no purl, no version): they are not
    packages, so they must not drag purl coverage under the bar and make every real SBOM inconclusive."""
    count, pct, problems = assess_quality(REAL)
    assert problems == [] and pct == 100.0
    assert count == 7  # six reusable workflows and pyyaml; the two files are not counted


def test_packages_without_purl_still_fail_the_bar():
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1"},
            {"type": "library", "name": "b", "version": "2"},
        ],
    }
    _, pct, problems = assess_quality(bom)
    assert pct == 50.0 and any("purl coverage" in p for p in problems)


def test_files_only_is_not_an_inventory():
    bom = {"bomFormat": "CycloneDX", "components": [{"type": "file", "name": "requirements.txt"}]}
    assert "no components" in assess_quality(bom)[2]
