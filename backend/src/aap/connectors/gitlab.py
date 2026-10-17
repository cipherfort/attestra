# SPDX-License-Identifier: Apache-2.0
"""GitLab adapter (M3, ADR-033): a read-only REST client and the component-job verification that decides whether a
job's evidence came from an approved CI/CD component.

The platform's token is a group access token: Reporter, scopes `read_api` + `read_repository`. Nothing here writes.

verify_component_job(): the job's commit is linted (merged CI configuration + includes); the evidence is accepted
only if (a) every include is local or pinned to a commit SHA, (b) an approved component at an approved SHA is
included, (c) the merged job equals the job rendered from the component file at that SHA, apart from scheduling keys,
and (d) the job inherits neither `default:` nor global `variables:`. See ADR-033 for why each check exists.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from aap.connectors.github_settings import Unavailable

MAX_PAGES = 50
SHA = re.compile(r"^[0-9a-f]{40}$")
SCHEDULING_KEYS = frozenset(
    {
        "stage",
        "tags",
        "needs",
        "rules",
        "when",
        "dependencies",
        "interruptible",
        "timeout",
        "retry",
        "resource_group",
        "environment",
    }
)
INPUT = re.compile(r"\$\[\[\s*inputs\.([A-Za-z0-9_-]+)\s*\]\]")


class GitLabRest:
    def __init__(self, token_provider: Callable[[], str], base_url: str, http: httpx.Client | None = None):
        self._token = token_provider
        self.base_url = base_url.rstrip("/")
        self._http = http or httpx.Client(base_url=f"{self.base_url}/api/v4", timeout=30.0, follow_redirects=False)

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self._token(), "Accept": "application/json"}

    @staticmethod
    def pid(project: str | int) -> str:
        return quote(str(project), safe="")

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        r = self._http.get(path, params=params, headers=self._headers())
        if r.status_code in (401, 403, 404):
            raise Unavailable(f"{r.status_code} on {path.split('?')[0]}")
        r.raise_for_status()
        return r.json()

    def pages(self, path: str, params: Mapping[str, Any] | None = None) -> Iterator[Any]:
        query: dict[str, Any] = {"per_page": 100, **(params or {})}
        for page in range(1, MAX_PAGES + 1):
            r = self._http.get(path, params={**query, "page": page}, headers=self._headers())
            if r.status_code in (401, 403, 404):
                raise Unavailable(f"{r.status_code} on {path}")
            r.raise_for_status()
            yield from r.json()
            if not r.headers.get("X-Next-Page"):
                return
        raise Unavailable(f"more than {MAX_PAGES} pages on {path}")

    def file(self, project: str | int, path: str, ref: str) -> str | None:
        r = self._http.get(
            f"/projects/{self.pid(project)}/repository/files/{quote(path, safe='')}/raw",
            params={"ref": ref},
            headers=self._headers(),
        )
        if r.status_code == 404:
            return None
        if r.status_code in (401, 403):
            raise Unavailable(f"{r.status_code} reading {path}")
        r.raise_for_status()
        return r.text

    def project(self, project: str | int) -> dict[str, Any]:
        return dict(self.get(f"/projects/{self.pid(project)}"))

    def job(self, project: str | int, job_id: int) -> dict[str, Any]:
        return dict(self.get(f"/projects/{self.pid(project)}/jobs/{int(job_id)}"))

    def lint(self, project: str | int, sha: str) -> dict[str, Any]:
        """The CI configuration that applies at `sha`, merged, with its includes (Reporter can read it: ADR-033)."""
        return dict(self.get(f"/projects/{self.pid(project)}/ci/lint", {"content_ref": sha, "include_jobs": "true"}))

    def artifacts(self, project: str | int, job_id: int, max_bytes: int) -> bytes:
        with self._http.stream(
            "GET", f"/projects/{self.pid(project)}/jobs/{int(job_id)}/artifacts", headers=self._headers()
        ) as r:
            if r.status_code in (401, 403, 404):
                raise Unavailable(f"{r.status_code} downloading job {job_id} artifacts")
            r.raise_for_status()
            data = bytearray()
            for chunk in r.iter_bytes():
                data += chunk
                if len(data) > max_bytes:
                    raise Unavailable(f"job {job_id} artifacts exceed {max_bytes} bytes")
            return bytes(data)


# ------------------------------------------------------------------------------------------ component verification


@dataclass(frozen=True)
class GitLabComponents:
    """config/trusted-producers.yaml → gitlab: which components (and commits of them) may produce evidence."""

    project: str  # e.g. example-org/security-components
    components: dict[str, dict[str, Any]]  # component name → {"job", "types", "shas"}

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> GitLabComponents:
        gl = cfg.get("gitlab") or {}
        comps = {}
        for c in gl.get("components") or []:
            shas = {
                (s["sha"] if isinstance(s, Mapping) else str(s))
                for s in c.get("approved_shas") or []
                if not (isinstance(s, Mapping) and s.get("revoked_at"))
            }
            comps[c["name"]] = {"job": c["job"], "types": set(c["evidence_types"]), "shas": shas}
        return cls(str(gl.get("components_project", "")), comps)


def render_component(text: str, job: str) -> dict[str, Any]:
    """The job a component defines, with inputs at their defaults (the shipped components have no other inputs)."""
    try:
        return _render_component(text, job)
    except (yaml.YAMLError, AttributeError, TypeError, IndexError) as e:
        raise ValueError(f"component file is malformed: {type(e).__name__}") from e


def _render_component(text: str, job: str) -> dict[str, Any]:
    docs = list(yaml.safe_load_all(text))
    if len(docs) == 2:
        spec, body_text = docs[0] or {}, text.split("\n---\n", 1)[1]
    else:
        spec, body_text = {}, text
    defaults = {k: (v or {}).get("default") for k, v in ((spec.get("spec") or {}).get("inputs") or {}).items()}

    def sub(m: re.Match[str]) -> str:
        if m.group(1) not in defaults or defaults[m.group(1)] is None:
            raise ValueError(f"input {m.group(1)!r} has no default")
        return str(defaults[m.group(1)])

    body = yaml.safe_load(INPUT.sub(sub, body_text)) or {}
    if not isinstance(body, dict) or job not in body or not isinstance(body[job], dict):
        raise ValueError(f"component defines no job {job!r}")
    return dict(body[job])


def _normalise(job: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in job.items() if k not in SCHEDULING_KEYS}


@dataclass(frozen=True)
class ComponentCheck:
    approved_ref: str | None  # "<components project>/<component>@<sha>" when the job is the approved component's
    known_component: bool  # an approved component is involved (so a failure is UNAPPROVED, not UNTRUSTED)
    detail: str


def verify_component_job(
    lint: Mapping[str, Any],
    job_name: str,
    evidence_type: str,
    trusted: GitLabComponents,
    component_file: Callable[[str, str, str], str | None],
) -> ComponentCheck:
    """Malformed input from GitLab can only produce a rejection, never an exception (fuzzed)."""
    try:
        return _verify_component_job(lint, job_name, evidence_type, trusted, component_file)
    except (yaml.YAMLError, AttributeError, TypeError, KeyError, IndexError, ValueError) as e:
        return ComponentCheck(None, False, f"CI configuration could not be read: {type(e).__name__}")


def _verify_component_job(
    lint: Mapping[str, Any],
    job_name: str,
    evidence_type: str,
    trusted: GitLabComponents,
    component_file: Callable[[str, str, str], str | None],
) -> ComponentCheck:
    if not lint.get("valid"):
        return ComponentCheck(None, False, f"CI configuration at the job's commit is not valid: {lint.get('errors')}")
    includes = lint.get("includes") or []
    unpinned = []
    for inc in includes:
        kind, loc = inc.get("type"), str(inc.get("location", ""))
        if kind == "local":
            continue
        ref = (
            loc.rsplit("@", 1)[1]
            if kind == "component" and "@" in loc
            else str((inc.get("extra") or {}).get("ref") or "")
        )
        if not SHA.match(ref):
            unpinned.append(f"{kind}:{loc}")
    if unpinned:
        return ComponentCheck(None, False, f"includes not pinned to a commit SHA: {', '.join(unpinned[:3])}")

    candidates = []
    for inc in includes:
        if inc.get("type") != "component":
            continue
        path, _, sha = str(inc["location"]).rpartition("@")
        name = path.rsplit("/", 1)[-1]
        project = path.split("/", 1)[1].rsplit("/", 1)[0] if "/" in path else ""
        comp = trusted.components.get(name)
        if project == trusted.project and comp and comp["job"] == job_name and evidence_type in comp["types"]:
            candidates.append((name, sha, comp))
    if not candidates:
        return ComponentCheck(None, False, f"job {job_name!r} is not from an approved component for {evidence_type}")
    name, sha, comp = candidates[0]
    if sha not in comp["shas"]:
        return ComponentCheck(None, True, f"component {name} at {sha[:12]} is not an approved commit")

    merged = yaml.safe_load(lint.get("merged_yaml") or "") or {}
    job = merged.get(job_name)
    if not isinstance(job, Mapping):
        return ComponentCheck(None, True, f"job {job_name!r} is not in the merged configuration")
    source = component_file(trusted.project, f"templates/{name}.yml", sha)
    if source is None:
        return ComponentCheck(None, True, f"component file templates/{name}.yml not readable at {sha[:12]}")
    try:
        expected = render_component(source, job_name)
    except ValueError as e:
        return ComponentCheck(None, True, f"component cannot be rendered: {e}")
    inherit = job.get("inherit") or {}
    if inherit.get("default") is not False or inherit.get("variables") is not False:
        return ComponentCheck(None, True, "job inherits project defaults or variables (inherit: default/variables)")
    got, want = _normalise(job), _normalise(expected)
    if got != want:
        changed = sorted(k for k in set(got) | set(want) if got.get(k) != want.get(k))
        return ComponentCheck(None, True, f"job differs from the approved component in: {', '.join(changed)}")
    return ComponentCheck(f"{trusted.project}/{name}@{sha}", True, "merged job equals the approved component")


def run_info(job: Mapping[str, Any], project_id: int, check: ComponentCheck) -> Any:
    """GitLab job → the RunInfo the provider-neutral verifier (domain/evidence.verify_bundle) understands."""
    from aap.domain.evidence import RunInfo

    status = {"success": "success", "failed": "failure"}.get(str(job.get("status")), str(job.get("status")))
    return RunInfo(
        run_id=int(job["id"]),
        run_attempt=1,
        repository_id=int(project_id),
        head_sha=str((job.get("commit") or {}).get("id") or job.get("sha") or ""),
        event=str((job.get("pipeline") or {}).get("source") or "push"),
        conclusion=status,
        referenced_workflows=(check.approved_ref,) if check.approved_ref else (),
    )


def trusted_workflows(trusted: GitLabComponents) -> Any:
    """Adapter onto domain.evidence.TrustedWorkflows: path = component name; every GitLab runner is capped at C2."""
    from aap.domain.evidence import TrustedWorkflows

    approved = {name: {"shas": c["shas"], "types": c["types"]} for name, c in trusted.components.items()}
    caps = {"github-hosted": "C2", "self-hosted-ephemeral": "C2", "self-hosted": "C2"}
    return TrustedWorkflows(trusted.project, approved, caps)


def bundles(files: Mapping[str, bytes], prefix: str = "aap-evidence-") -> dict[str, dict[str, bytes]]:
    """A GitLab job has one artifacts archive; each evidence bundle is a top-level `aap-evidence-<name>/` folder."""
    out: dict[str, dict[str, bytes]] = {}
    for path, data in files.items():
        top, _, rest = path.partition("/")
        if top.startswith(prefix) and rest and "/" not in rest:
            out.setdefault(top, {})[rest] = data
    return out


def required_component_checks(lint: Mapping[str, Any], trusted: GitLabComponents) -> list[str]:
    """Approved component jobs present in a configuration, named as the catalogue names checks ("aap / sast")."""
    merged = yaml.safe_load(lint.get("merged_yaml") or "") or {}
    names = []
    for name, comp in trusted.components.items():
        if comp["job"] in merged:
            names.append(f"aap / {name}")
    return sorted(names)


def owners_from_codeowners(content: str) -> list[tuple[str, list[str]]]:
    """GitLab CODEOWNERS: sections ([Name] @default-owner) are allowed; a section's default owners apply to its
    entries without owners."""
    rules: list[tuple[str, list[str]]] = []
    section_owners: list[str] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\^?\[[^\]]+\](?:\[\d+\])?\s*(.*)$", line)
        if m:
            section_owners = m.group(1).split()
            continue
        pattern, *owners = line.split()
        rules.append((pattern, owners or section_owners))
    return rules
