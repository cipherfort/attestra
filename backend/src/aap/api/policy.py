# SPDX-License-Identifier: Apache-2.0
"""Authorisation policy (ADR-013, access control model §3). One place decides; routes only declare permissions.

Deny by default: a permission not granted by any of the caller's roles is refused. Out-of-scope resources are
filtered by row-level security and surface as 404 (no enumeration).
"""

from __future__ import annotations

from dataclasses import dataclass, field

READ_CORE = frozenset(
    {
        "application.read",
        "evidence.read",
        "finding.read",
        "exception.read",
        "assessment.read",
        "catalogue.read",
        "org_unit.read",
        "vulnerability.read",
        "vulnerability.impact.read",
        "component.read",
        "authenticated",
        "job.read.own",
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "engineer": READ_CORE | {"finding.transition", "exception.request"},
    "champion": READ_CORE
    | {
        "finding.transition",
        "exception.request",
        "evidence.raw.read",
        "application.settings.write",
        "application.register",
        "assessment.create",
        "assessment.answer",
    },
    "app_owner": READ_CORE | {"exception.request", "exception.cosign"},
    "unit_lead": READ_CORE
    | {
        "application.register",
        "assessment.create",
        "assessment.answer",
        "exception.decide",
        "maturity.rollup.read",
        "report.export",
        "vulnerability.impact.export",
        "application.settings.write",
    },
    "appsec_engineer": READ_CORE
    | {
        "evidence.raw.read",
        "finding.transition",
        "finding.fp.confirm",
        "finding.priority.override",
        "classification.decide",
        "integration.read",
        "application.register",
        "assessment.create",
        "assessment.answer",
        "assessment.approve",
        "exception.decide",
        "maturity.rollup.read",
        "report.org.read",
        "report.export",
        "vulnerability.impact.export",
    },
    "governance_analyst": READ_CORE | {"maturity.rollup.read", "report.org.read", "report.export"},
    "security_leadership": READ_CORE
    | {
        "evidence.raw.read",
        "exception.decide",
        "maturity.rollup.read",
        "report.org.read",
        "report.export",
        "vulnerability.impact.export",
        "integration.read",
    },
    "executive": frozenset(
        {"authenticated", "catalogue.read", "org_unit.read", "maturity.rollup.read", "report.org.read"}
    ),
    "auditor": READ_CORE | {"evidence.raw.read", "maturity.rollup.read", "report.org.read"},
    # service client (Entra app role `Reports.Read`, client credentials): aggregates only, like executive
    "reports_reader": frozenset(
        {"authenticated", "catalogue.read", "org_unit.read", "maturity.rollup.read", "report.org.read"}
    ),
    "platform_admin": frozenset(
        {"authenticated", "catalogue.read", "org_unit.read", "job.read.own", "integration.read", "org.admin"}
    ),
}

# Roles whose data scope is the whole organisation (still subject to their permission set).
ORG_WIDE = frozenset(
    {"appsec_engineer", "governance_analyst", "security_leadership", "executive", "auditor", "reports_reader"}
)

# Roles an identity provider may assert directly (app roles in the token's `roles` claim, e.g. Entra app roles assigned
# through groups by examples/terraform/azure/modules/entra, or Keycloak client roles). Scoped roles (champion,
# app_owner, unit_lead) are never taken from a token: their scope lives in the platform (role_assignments, by user or
# by app-assigned IdP group).
TOKEN_ROLES = frozenset(
    {
        "engineer",
        "appsec_engineer",
        "governance_analyst",
        "security_leadership",
        "executive",
        "auditor",
        "platform_admin",
    }
)
SERVICE_ROLES = {"Reports.Read": "reports_reader"}  # app-only tokens (client credentials)

# Exception approval authority by rank (config/exception-policy.yaml role_rank).
APPROVER_ROLE_FOR = {
    "appsec_engineer": "appsec_engineer",
    "unit_lead": "unit_security_lead",
    "security_leadership": "head_of_appsec",
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    display_name: str
    roles: tuple[str, ...]
    org_units: tuple[str, ...] = ()  # expanded (descendants included) units the caller belongs to or leads
    kind: str = "user"
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def permissions(self) -> frozenset[str]:
        perms: set[str] = {"authenticated"}  # a signed-in principal with no role yet can still see who they are
        for r in self.roles:
            perms |= ROLE_PERMISSIONS.get(r, frozenset())
        return frozenset(perms)

    @property
    def org_wide(self) -> bool:
        return bool(ORG_WIDE & set(self.roles))

    def can(self, permission: str) -> bool:
        return permission == "public" or permission in self.permissions
