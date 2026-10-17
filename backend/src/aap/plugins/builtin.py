# SPDX-License-Identifier: Apache-2.0
"""The integrations that ship with the platform, registered through the same entry point a third party would use
(pyproject.toml: [project.entry-points."aap.plugins"] builtin = "aap.plugins.builtin:PLUGINS")."""

from __future__ import annotations

from aap.plugins import Plugin, RunContext, RunResult


def _run(name: str, with_blobs: bool = False):  # type: ignore[no-untyped-def]
    def run(ctx: RunContext) -> RunResult:
        from aap.worker import connectors  # lazy: plugin discovery must not import every SDK

        fn = getattr(connectors, name)
        args = (ctx.engine, ctx.bundle, ctx.secrets, ctx.payload) + ((ctx.blobs,) if with_blobs else ())
        result: RunResult = fn(*args)
        return result

    return run


PLUGINS = [
    Plugin(
        key="github",
        name="GitHub App",
        kind="scm",
        purpose="Repository settings, workflow evidence, secret scanning",
        env=("AAP_GITHUB_APP_CLIENT_ID", "AAP_GITHUB_ORG"),
        secrets=("github-app-private-key",),
        bootstrap="aap bootstrap github-app --org <org>",
        evidence=("repo.*", "registry.application", "scan.secrets", "workflow evidence"),
        interval="github.settings_sync_interval",
        run=_run("github"),
    ),
    Plugin(
        key="gitlab",
        name="GitLab",
        kind="scm",
        purpose="Project settings, CI component evidence (capped at C2, ADR-033), discovery",
        env=("AAP_GITLAB_URL", "AAP_GITLAB_GROUP"),
        secrets=("gitlab-token",),
        bootstrap="aap bootstrap gitlab --url <https://gitlab.example.org> --group <group>",
        evidence=("repo.*", "registry.application", "component evidence"),
        interval="gitlab.settings_sync_interval",
        run=_run("gitlab"),
    ),
    Plugin(
        key="oidc",
        name="Sign-in (OpenID Connect)",
        kind="identity",
        purpose="Workforce sign-in, app roles, groups (Entra ID, Okta, Keycloak, any OIDC provider)",
        env=("AAP_OIDC_ISSUER", "AAP_OIDC_CLIENT_ID", "AAP_PUBLIC_URL"),
        bootstrap="your identity provider's app registration (Entra: examples/terraform/azure/modules/entra)",
    ),
    Plugin(
        key="jira",
        name="Jira",
        kind="ticketing",
        purpose="Remediation tickets (the platform is the only writer)",
        env=("AAP_JIRA_URL", "AAP_JIRA_EMAIL"),
        secrets=("jira-api-token",),
        bootstrap="aap bootstrap jira",
        interval="jira.reconcile_interval",
        run=_run("jira"),
    ),
    Plugin(
        key="github_issues",
        name="GitHub Issues",
        kind="ticketing",
        purpose="Remediation issues in a GitHub repository (the platform is the only writer)",
        env=("AAP_GITHUB_APP_CLIENT_ID", "AAP_GITHUB_ISSUES"),
        secrets=("github-app-private-key",),
        bootstrap="aap bootstrap github-app --with-issues; set AAP_GITHUB_ISSUES=on and github_issues in "
        "config/integrations.yaml",
        interval="github_issues.reconcile_interval",
        run=_run("github_issues"),
    ),
    Plugin(
        key="gitlab_issues",
        name="GitLab Issues",
        kind="ticketing",
        purpose="Remediation issues in a GitLab project (the platform is the only writer)",
        env=("AAP_GITLAB_URL",),
        secrets=("gitlab-issues-token",),
        bootstrap="aap bootstrap gitlab --with-issues; set gitlab_issues in config/integrations.yaml",
        interval="gitlab_issues.reconcile_interval",
        run=_run("gitlab_issues"),
    ),
    Plugin(
        key="osv",
        name="OSV (built in)",
        kind="vuln_intel",
        purpose="Advisories for every SBOM component, matched by package URL (api.osv.dev; no account)",
        bootstrap="nothing to set up; allow egress to api.osv.dev (or set AAP_OSV_API to a mirror)",
        evidence=("dependency findings",),
        interval="vuln_feeds.osv_sync_interval",
        run=_run("osv"),
    ),
    Plugin(
        key="cisa_kev",
        name="CISA KEV (built in)",
        kind="vuln_intel",
        purpose="Known exploited vulnerabilities: raises affected findings' priority",
        bootstrap="nothing to set up; allow egress to www.cisa.gov (or set AAP_KEV_URL to a mirror)",
        interval="vuln_feeds.kev_sync_interval",
        run=_run("cisa_kev"),
    ),
    Plugin(
        key="epss",
        name="FIRST EPSS (built in)",
        kind="vuln_intel",
        purpose="Exploit prediction scores for the CVEs the platform holds",
        bootstrap="nothing to set up; allow egress to api.first.org (or set AAP_EPSS_API to a mirror)",
        interval="vuln_feeds.epss_sync_interval",
        run=_run("epss"),
    ),
    Plugin(
        key="endoflife",
        name="endoflife.date (built in)",
        kind="vuln_intel",
        purpose="End-of-life runtimes and frameworks in current SBOMs (config/eol-products.yaml)",
        bootstrap="nothing to set up; allow egress to endoflife.date (or set AAP_EOL_API to a mirror)",
        evidence=("sbom.eol",),
        interval="vuln_feeds.eol_sync_interval",
        run=_run("endoflife"),
    ),
    Plugin(
        key="siem_http",
        name="SIEM over HTTPS (JSON or Splunk HEC)",
        kind="siem",
        purpose="Curated security events to Splunk (HEC), Elastic, Sumo Logic or any HTTPS collector",
        env=("AAP_SIEM_HTTP_URL",),
        secrets=("siem-http-token",),
        bootstrap="create a HEC/ingest token in your SIEM, then: aap secrets put siem-http-token; set "
        "AAP_SIEM_HTTP_FORMAT=splunk_hec for Splunk",
        interval="siem.dispatch_interval",
        run=_run("siem_http"),
    ),
    Plugin(
        key="syslog",
        name="SIEM over syslog (RFC 5424, TLS)",
        kind="siem",
        purpose="Curated security events to any syslog collector over TLS (RFC 5425)",
        env=("AAP_SIEM_SYSLOG",),
        bootstrap="a TLS syslog listener (usually port 6514); AAP_SIEM_SYSLOG=host:port, AAP_SIEM_SYSLOG_CA if private",
        interval="siem.dispatch_interval",
        run=_run("syslog"),
    ),
    Plugin(
        key="webhook",
        name="Chat notifications (incoming webhook)",
        kind="notification",
        purpose="Pending approvals, expiring exceptions and new P1 findings to a Slack/Teams/Mattermost channel",
        secrets=("notify-webhook-url",),
        bootstrap="create an incoming webhook in your chat tool, then: aap secrets put notify-webhook-url",
        interval="notifications.dispatch_interval",
        run=_run("webhook"),
    ),
    Plugin(
        key="dependency_track",
        name="Dependency-Track",
        kind="vuln_intel",
        purpose="Continuous SBOM analysis against new advisories (optional)",
        env=("AAP_DT_URL",),
        secrets=("dependency-track-api-key",),
        bootstrap="aap bootstrap dependency-track",
        evidence=("dependency findings",),
        interval="dependency_track.findings_sync_interval",
        run=_run("dependency_track", with_blobs=True),
    ),
    Plugin(
        key="defectdojo",
        name="DefectDojo",
        kind="workbench",
        purpose="Optional triage workbench (scans forwarded on ingest)",
        env=("AAP_DD_URL",),
        secrets=("defectdojo-api-token",),
        bootstrap="aap bootstrap defectdojo",
        run=_run("defectdojo", with_blobs=True),
    ),
    Plugin(
        key="azure",
        name="Microsoft Defender for Cloud",
        kind="cloud_posture",
        purpose="Cloud posture findings on mapped subscriptions and resource groups",
        env=("AAP_AZURE_SUBSCRIPTIONS",),
        bootstrap="reader roles (example: examples/terraform/azure/modules/azure-reader)",
        evidence=("cloud.posture",),
        interval="cloud.azure.defender_sync_interval",
        run=_run("azure"),
    ),
    Plugin(
        key="aws",
        name="AWS Security Hub",
        kind="cloud_posture",
        purpose="Cloud posture findings on mapped accounts",
        env=("AAP_AWS_ROLE_ARN", "AAP_AWS_ACCOUNTS"),
        bootstrap="a read-only role (example: examples/terraform/azure/modules/aws-reader)",
        evidence=("cloud.posture",),
        interval="cloud.aws.securityhub_sync_interval",
        run=_run("aws"),
    ),
    Plugin(
        key="sentinel",
        name="Microsoft Sentinel",
        kind="siem",
        purpose="Curated security events and daily evidence checkpoints",
        env=("AAP_SENTINEL_DCE", "AAP_SENTINEL_DCR_ID"),
        bootstrap="a data collection rule (example: examples/terraform/azure/modules/sentinel)",
        interval="siem.dispatch_interval",
        run=_run("sentinel"),
    ),
]
