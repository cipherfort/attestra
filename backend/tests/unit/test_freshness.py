# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta

import pytest

from aap.domain.freshness import EvidenceState, FreshnessFacts, evaluate, path_matches


def test_glob_semantics():
    assert path_matches("main.tf", ["**/*.tf"])
    assert path_matches("infra/modules/net/main.tf", ["**/*.tf"])
    assert not path_matches("README.md", ["**/*.tf"])
    assert path_matches(".security/threat-model/threats.yaml", [".security/threat-model/**"])
    assert not path_matches("src/a.py", ["*.py"])  # * stays inside one directory


def test_commit_bound_superseded_only_by_meaningful_change(bundle, now):
    sast = bundle.evidence_types["scan.sast"]["freshness"]
    iac = bundle.evidence_types["scan.iac"]["freshness"]
    observed = now - timedelta(days=2)
    facts = FreshnessFacts(now=now, changed_paths=("README.md",))
    assert evaluate(observed, iac, facts).state is EvidenceState.ACTIVE  # docs change doesn't stale an IaC scan
    assert evaluate(observed, sast, facts).state is EvidenceState.SUPERSEDED  # SAST watches every path
    r = evaluate(observed, iac, FreshnessFacts(now=now, changed_paths=("infra/main.tf",)))
    assert r.state is EvidenceState.SUPERSEDED and "infra/main.tf" in r.reason


def test_commit_bound_fails_safe_when_compare_truncated(bundle, now):
    r = evaluate(
        now,
        bundle.evidence_types["scan.iac"]["freshness"],
        FreshnessFacts(now=now, changed_paths=(), compare_truncated=True),
    )
    assert r.state is EvidenceState.SUPERSEDED


def test_ceiling_and_warning(bundle, now):
    policy = bundle.evidence_types["scan.sast"]["freshness"]  # ceiling 30d, warn 5d
    assert evaluate(now - timedelta(days=26), policy, FreshnessFacts(now=now)).state is EvidenceState.EXPIRING
    assert evaluate(now - timedelta(days=31), policy, FreshnessFacts(now=now)).state is EvidenceState.EXPIRED


def test_continuous_requires_reconfirmation(bundle, now):
    policy = bundle.evidence_types["repo.ruleset"]["freshness"]  # ttl 24h
    stale = evaluate(now - timedelta(hours=30), policy, FreshnessFacts(now=now))
    assert stale.state is EvidenceState.EXPIRED
    fresh = evaluate(
        now - timedelta(hours=30), policy, FreshnessFacts(now=now, last_confirmed=now - timedelta(hours=1))
    )
    assert fresh.state is EvidenceState.ACTIVE


def test_event_bound_invalidated_by_architecture_change(bundle, now):
    policy = bundle.evidence_types["assessment.threat_model"]["freshness"]
    r = evaluate(
        now - timedelta(days=10), policy, FreshnessFacts(now=now, events_since=frozenset({"architecture_change"}))
    )
    assert r.state is EvidenceState.SUPERSEDED and "architecture_change" in r.reason


def test_artifact_bound_superseded_when_digest_not_current(bundle, now):
    r = evaluate(now, bundle.evidence_types["sbom"]["freshness"], FreshnessFacts(now=now, digest_current=False))
    assert r.state is EvidenceState.SUPERSEDED


def test_revoked_wins(bundle, now):
    assert (
        evaluate(now, bundle.evidence_types["sbom"]["freshness"], FreshnessFacts(now=now, revoked=True)).state
        is EvidenceState.REVOKED
    )


def test_every_configured_policy_is_understood(bundle, now):
    for name, t in bundle.evidence_types.items():
        try:
            evaluate(now - timedelta(days=1), t["freshness"], FreshnessFacts(now=now))
        except Exception as e:  # pragma: no cover - failure path is the assertion
            pytest.fail(f"{name}: {e}")
