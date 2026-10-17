# SPDX-License-Identifier: Apache-2.0
"""Reading a repository's contract through the GitHub plugin (recorded API shapes, real client, mock transport)."""

from __future__ import annotations

import httpx
import pytest

from aap.config import repo_root
from aap.connectors.github_settings import GitHubRest
from aap.services.onboarding import OnboardingError, fetch_contract

APP_YAML = (repo_root() / "templates/repo-contract/.security/application.yaml").read_text()


def api(files: dict[str, str], repo_status: int = 200, commits: int = 200) -> GitHubRest:
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/repos/example-org/claims-api":
            if repo_status != 200:
                return httpx.Response(repo_status)
            return httpx.Response(
                200,
                json={
                    "id": 42,
                    "full_name": "example-org/claims-api",
                    "default_branch": "trunk",
                    "visibility": "internal",
                },
            )
        if path == "/repos/example-org/claims-api/commits/trunk":
            return httpx.Response(commits, json={"sha": "a" * 40} if commits == 200 else {})
        prefix = "/repos/example-org/claims-api/contents/"
        if path.startswith(prefix):
            assert req.url.params["ref"] == "trunk"  # read from the default branch, not whatever HEAD is
            body = files.get(path.removeprefix(prefix))
            return httpx.Response(200, text=body) if body is not None else httpx.Response(404)
        return httpx.Response(404)

    return GitHubRest(
        lambda: "token", http=httpx.Client(base_url="https://api.github.test", transport=httpx.MockTransport(handler))
    )


def test_reads_identity_and_both_files_from_the_default_branch():
    ref, app_doc, asvs_doc = fetch_contract(
        api({".security/application.yaml": APP_YAML, ".security/asvs.yaml": "target_level: L2\n"}),
        "example-org/claims-api",
    )
    assert (ref.provider, ref.external_id, ref.default_branch, ref.visibility) == ("github", "42", "trunk", "internal")
    assert ref.head_sha == "a" * 40
    assert app_doc["application"]["name"] == "Claims API" and asvs_doc == {"target_level": "L2"}


def test_empty_repository_has_no_head_but_still_reads():
    ref, _, asvs = fetch_contract(api({".security/application.yaml": APP_YAML}, commits=409), "example-org/claims-api")
    assert ref.head_sha is None and asvs is None


def test_missing_contract_and_invisible_repository_are_explained():
    with pytest.raises(OnboardingError) as missing:
        fetch_contract(api({}), "example-org/claims-api")
    assert missing.value.status == 422 and "templates/repo-contract" in missing.value.problems[0]
    with pytest.raises(OnboardingError) as hidden:
        fetch_contract(api({}, repo_status=404), "example-org/claims-api")
    assert hidden.value.status == 404 and "install the App" in hidden.value.problems[0]
    with pytest.raises(OnboardingError, match="not valid YAML"):
        fetch_contract(api({".security/application.yaml": "a: [unclosed"}), "example-org/claims-api")
