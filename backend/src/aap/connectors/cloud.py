# SPDX-License-Identifier: Apache-2.0
"""Cloud posture connectors (ADR-019): Microsoft Defender for Cloud and AWS Security Hub, read-only.

Azure: Azure Resource Graph (`securityresources`, unhealthy assessments) with the platform's managed identity, which
       examples/terraform/azure/modules/azure-reader grants Reader + Security Reader on the scopes the organisation
       chooses.
AWS:   Security Hub `GetFindings` in each configured account/region, through a role assumed with web identity: the
       managed identity's Entra token is exchanged at AWS STS (IAM OIDC provider trusting the Entra tenant, created by
       examples/terraform/azure/modules/aws-reader). No AWS access keys exist anywhere.

Both return `CloudFinding`s; mapping to applications (cloud_scopes) happens in services/cloud_sync.py.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
ARM_SCOPE = "https://management.azure.com/.default"
SEVERITIES = ("low", "medium", "high", "critical")

DEFENDER_QUERY = """securityresources
| where type == "microsoft.security/assessments"
| where tostring(properties.status.code) == "Unhealthy"
| extend severity = tolower(tostring(properties.metadata.severity)),
         resourceId = tolower(tostring(properties.resourceDetails.Id)),
         title = tostring(properties.displayName),
         firstSeen = tostring(properties.status.firstEvaluationDate)
| project id, severity, resourceId, title, firstSeen, subscriptionId
| order by id asc"""


class CloudConnectorError(Exception):
    pass


@dataclass(frozen=True)
class CloudFinding:
    provider: str  # azure | aws
    source: str  # defender | security_hub (source_system enum)
    id: str
    severity: str  # low | medium | high | critical
    title: str
    resource_id: str
    account: str  # subscription id / AWS account id
    tags: tuple[tuple[str, str], ...] = ()
    first_seen: str | None = None


class DefenderClient:
    def __init__(self, token: Callable[[], str], http: httpx.Client | None = None):
        self._token = token
        self._http = http or httpx.Client(timeout=60.0, follow_redirects=False)

    def unhealthy(self, subscriptions: Sequence[str], max_pages: int = 50) -> Iterator[CloudFinding]:
        skip: str | None = None
        for _ in range(max_pages):
            options: dict[str, Any] = {"$top": 1000, "resultFormat": "objectArray"}
            if skip:
                options["$skipToken"] = skip
            r = self._http.post(
                ARG_URL,
                headers={"Authorization": f"Bearer {self._token()}"},
                json={"subscriptions": list(subscriptions), "query": DEFENDER_QUERY, "options": options},
            )
            if r.status_code in (401, 403):
                raise CloudConnectorError(f"Resource Graph refused ({r.status_code}): Reader + Security Reader needed")
            r.raise_for_status()
            body = r.json()
            for row in body.get("data", []):
                sev = row.get("severity") if row.get("severity") in SEVERITIES else "medium"
                yield CloudFinding(
                    "azure",
                    "defender",
                    row["id"],
                    sev,
                    row.get("title") or "",
                    row.get("resourceId") or "",
                    row.get("subscriptionId") or "",
                    first_seen=row.get("firstSeen"),
                )
            skip = body.get("$skipToken")
            if not skip:
                return
        raise CloudConnectorError(f"more than {max_pages} pages of Defender assessments")


def azure_token(credential: Any) -> Callable[[], str]:
    return lambda: str(credential.get_token(ARM_SCOPE).token)


class SecurityHubClient:
    """`session_factory()` returns a boto3 Session with temporary credentials (see `web_identity_session`)."""

    def __init__(self, session_factory: Callable[[], Any], regions: Sequence[str]):
        self._session = session_factory
        self._regions = list(regions)

    def active(self, account_ids: Sequence[str]) -> Iterator[CloudFinding]:
        session = self._session()
        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": v, "Comparison": "EQUALS"} for v in ("NEW", "NOTIFIED")],
            "SeverityLabel": [{"Value": v, "Comparison": "EQUALS"} for v in ("MEDIUM", "HIGH", "CRITICAL")],
            "AwsAccountId": [{"Value": a, "Comparison": "EQUALS"} for a in account_ids],
        }
        wanted_accounts, wanted_sev = set(account_ids), {"medium", "high", "critical"}
        for region in self._regions:
            client = session.client("securityhub", region_name=region)
            for page in client.get_paginator("get_findings").paginate(
                Filters=filters, PaginationConfig={"MaxItems": 20000}
            ):
                for f in page["Findings"]:
                    res = (f.get("Resources") or [{}])[0]
                    sev = str((f.get("Severity") or {}).get("Label", "MEDIUM")).lower()
                    # the API filter is authoritative, but never trust it alone: re-check scope client-side
                    if f.get("AwsAccountId") not in wanted_accounts or sev not in wanted_sev:
                        continue
                    if f.get("RecordState", "ACTIVE") != "ACTIVE":
                        continue
                    yield CloudFinding(
                        "aws",
                        "security_hub",
                        f["Id"],
                        sev if sev in SEVERITIES else "medium",
                        f.get("Title", ""),
                        res.get("Id", ""),
                        f.get("AwsAccountId", ""),
                        tuple(sorted((res.get("Tags") or {}).items())),
                        f.get("FirstObservedAt") or f.get("CreatedAt"),
                    )


def web_identity_session(
    role_arn: str, token: Callable[[], str], region: str, sts_client: Any | None = None
) -> Callable[[], Any]:
    """AssumeRoleWithWebIdentity with the managed identity's Entra token (1 h credentials, new session per sync)."""
    import boto3

    def factory() -> Any:
        sts = sts_client or boto3.client("sts", region_name=region)
        creds = sts.assume_role_with_web_identity(
            RoleArn=role_arn, RoleSessionName="aap-platform", WebIdentityToken=token(), DurationSeconds=3600
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    return factory


def entra_web_identity_token(credential: Any, audience: str = "api://AzureADTokenExchange") -> Callable[[], str]:
    return lambda: str(credential.get_token(f"{audience}/.default").token)
