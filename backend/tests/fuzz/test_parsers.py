# SPDX-License-Identifier: Apache-2.0
"""Property-based fuzzing (Hypothesis) of every parser that reads untrusted input: evidence archives and manifests,
SARIF, CycloneDX, JUnit, webhook payloads, CVSS vectors, GitLab component files and contract files.

The property for each: any input either parses or fails with the parser's own error type. Never an unhandled
exception (a crash is a denial of service at best, and a sign of an unchecked assumption at worst).
Deeper runs: HYPOTHESIS_PROFILE=fuzz (nightly CI)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import zipfile

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aap.connectors.gitlab import GitLabComponents, bundles, render_component, verify_component_job
from aap.domain.cvss import CvssError, base_score
from aap.domain.evidence import RunInfo, TrustedWorkflows, verify_bundle
from aap.hook.app import gitlab_jobs_for, jobs_for
from aap.ingest.parsers import BundleError, load_json, parse_junit, parse_sarif, safe_unzip, sbom_summary
from aap.ingest.pipeline import manifest_errors

settings.register_profile("default", max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("fuzz", max_examples=5000, deadline=None, suppress_health_check=list(HealthCheck))
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

scalars = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=40)
json_values = st.recursive(
    scalars, lambda c: st.lists(c, max_size=5) | st.dictionaries(st.text(max_size=12), c, max_size=6), max_leaves=40
)


def sarif_like():
    result = st.fixed_dictionaries(
        {},
        optional={
            "ruleId": json_values,
            "level": json_values,
            "message": json_values,
            "locations": json_values,
            "properties": json_values,
            "partialFingerprints": json_values,
            "suppressions": json_values,
        },
    )
    run = st.fixed_dictionaries(
        {},
        optional={
            "tool": st.fixed_dictionaries(
                {},
                optional={
                    "driver": json_values
                    | st.fixed_dictionaries(
                        {}, optional={"name": json_values, "rules": st.lists(json_values, max_size=3)}
                    )
                },
            ),
            "results": st.lists(result | json_values, max_size=4),
        },
    )
    return st.fixed_dictionaries(
        {"version": st.sampled_from(["2.1.0", "2.1", "2.0.0"]) | json_values},
        optional={"runs": st.lists(run | json_values, max_size=3) | json_values},
    )


@given(sarif_like() | json_values)
def test_sarif_never_crashes(doc):
    try:
        summary, results = parse_sarif(doc)
    except BundleError:
        return
    assert summary["results"] == len(results)


@given(json_values)
def test_sbom_summary_never_crashes(doc):
    with contextlib.suppress(BundleError):
        sbom_summary(doc)


@given(json_values)
def test_manifest_validation_never_crashes(doc):
    errors = manifest_errors(doc)
    if errors:
        return
    run = RunInfo(1, 1, 1, "a" * 40, "push", "success", ())
    verify_bundle(doc, {}, run, None, TrustedWorkflows("o/r", {}, {}), errors)


@given(st.binary(max_size=4096))
def test_unzip_never_crashes_on_bytes(data):
    with contextlib.suppress(BundleError):
        safe_unzip(data)


@given(st.lists(st.tuples(st.text(min_size=1, max_size=60), st.binary(max_size=64)), max_size=8))
def test_unzip_refuses_unsafe_paths(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            try:
                z.writestr(name, data)
            except (ValueError, UnicodeEncodeError):
                continue
    try:
        out = safe_unzip(buf.getvalue())
    except BundleError:
        return
    for name in out:
        assert not name.startswith("/") and ".." not in name.split("/") and "\\\\" not in name
    bundles(out)


@given(st.binary(max_size=2048) | st.text(max_size=2048).map(str.encode))
def test_junit_never_crashes(data):
    with contextlib.suppress(BundleError):
        parse_junit(data)


@given(st.binary(max_size=1024))
def test_load_json_never_crashes(data):
    with contextlib.suppress(BundleError, ValueError):
        load_json(data)


@given(json_values, st.text(max_size=20))
def test_webhook_mapping_never_crashes(payload, event):
    if isinstance(payload, dict):
        jobs_for(event, payload)
        gitlab_jobs_for(event, payload)


@given(
    st.text(max_size=120)
    | st.sampled_from(["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]).map(lambda v: v.replace("H", "X"))
)
def test_cvss_never_crashes(vector):
    try:
        score = base_score(vector)
    except CvssError:
        return
    assert 0 <= score <= 10


@given(st.text(max_size=400), st.text(max_size=20))
def test_component_render_never_crashes(text, job):
    with contextlib.suppress(ValueError):
        render_component(text, job)


@given(json_values)
def test_component_verifier_only_rejects_malformed_lint(lint):
    if not isinstance(lint, dict):
        return
    trusted = GitLabComponents("g/p", {"x": {"job": "aap-x", "types": {"scan.sast"}, "shas": {"a" * 40}}})
    check = verify_component_job(lint, "aap-x", "scan.sast", trusted, lambda *a: None)
    assert check.approved_ref is None  # nothing random is ever an approved component


@given(json_values)
def test_contract_schema_check_never_crashes(doc):
    from aap.services.onboarding import _schema_errors

    _schema_errors(doc, "application.schema.json")
    json.dumps(doc, default=str)
