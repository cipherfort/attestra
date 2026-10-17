# SPDX-License-Identifier: Apache-2.0
import pytest

from aap.domain.expressions import ExpressionError, compile_expression

CTX = {
    "app": {"exposure": "internet_public", "tier": 1},
    "vuln": {"in_cisa_kev": True, "exploit_public": False},
    "finding": {"requires_auth": False, "cvss_impact": {"integrity": "high"}, "type": "secret"},
}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("vuln.in_cisa_kev", True),
        ("vuln.exploit_public and not vuln.in_cisa_kev", False),
        ("app.exposure in ['internet_public', 'internet_authenticated']", True),
        ("finding.requires_auth == false", True),
        ("finding.cvss_impact.integrity == 'high'", True),
        ("finding.type in ['secret','malicious_package']", True),
        ("app.tier <= 2", True),
        ("finding.reachability == 'unreachable'", False),  # missing attribute → null
        ("finding.reachability > 3", False),  # ordering with null is false, never an error
        ("size(app.missing) == 0", True),
    ],
)
def test_evaluates_allowed_constructs(source, expected):
    assert compile_expression(source).test(CTX) is expected


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('id')",
        "app.__class__",
        "open('/etc/passwd')",
        "[x for x in app]",
        "lambda: 1",
        "app['exposure']",
        "app.exposure.upper()",
        "1 if app else 2",
        "app.tier * 1000",
    ],
)
def test_rejects_code_execution_and_other_constructs(source):
    with pytest.raises(ExpressionError):
        compile_expression(source)


def test_rejects_unknown_roots_when_restricted():
    with pytest.raises(ExpressionError, match="unknown names"):
        compile_expression("secrets.token == 'x'", {"app", "finding"})


def test_all_risk_model_expressions_compile(bundle):
    assert len(bundle.risk_expressions) >= 10
