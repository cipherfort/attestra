# SPDX-License-Identifier: Apache-2.0
"""aap.yaml settings: schema-validated, environment wins, no place for secrets; mounted secrets; database URL file."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
import yaml

from aap.config import repo_root
from aap.secrets import MountedSecretStore, SecretError
from aap.settings import MAPPING, SettingsError, apply, load


def write(tmp_path: Path, doc: dict) -> Path:
    p = tmp_path / "aap.yaml"
    p.write_text(yaml.safe_dump(doc))
    return p


def test_example_file_is_valid_and_maps_to_known_variables():
    values = load(repo_root() / "deploy" / "aap.example.yaml")
    assert values["AAP_BLOB_S3_BUCKET"] == "acme-aap-evidence" and values["AAP_SECRETS_BACKEND"] == "mounted"
    assert set(values) <= set(MAPPING.values())


def test_environment_wins_and_lists_join(tmp_path):
    f = write(
        tmp_path,
        {
            "version": 1,
            "public_url": "https://a.example",
            "plugins": {"aws_securityhub": {"accounts": ["111111111111", "222222222222"]}},
        },
    )
    env = {"AAP_CONFIG_FILE": str(f), "AAP_PUBLIC_URL": "https://override.example"}
    applied = apply(env)
    assert env["AAP_PUBLIC_URL"] == "https://override.example" and "AAP_PUBLIC_URL" not in applied
    assert env["AAP_AWS_ACCOUNTS"] == "111111111111,222222222222"


@pytest.mark.parametrize(
    "doc,why",
    [
        ({"plugins": {"jira": {"url": "https://x", "api_token": "s3cret"}}}, "api_token"),  # secrets have no place here
        ({"database": {"url": "postgresql://u:p@h/db"}}, "url"),  # use url_file
        ({"evidence_store": {"kind": "ftp"}}, "ftp"),
        ({"unknown_section": {}}, "unknown_section"),
    ],
)
def test_invalid_or_secret_bearing_files_refused(tmp_path, doc, why):
    with pytest.raises(SettingsError, match=why):
        load(write(tmp_path, doc))


def test_no_file_no_change():
    env = {"AAP_PUBLIC_URL": "x"}
    assert apply(env) == {} and env == {"AAP_PUBLIC_URL": "x"}


def test_mounted_secrets_are_read_only_and_not_world_readable(tmp_path):
    (tmp_path / "jira-api-token").write_text("tok\n")
    os.chmod(tmp_path / "jira-api-token", 0o440)
    store = MountedSecretStore(tmp_path)
    assert store.get("jira-api-token") == "tok" and store.get("missing") is None
    with pytest.raises(SecretError, match="read-only"):
        store.put("x", "y")
    os.chmod(tmp_path / "jira-api-token", 0o444)
    with pytest.raises(SecretError, match="world-accessible"):
        store.get("jira-api-token")
    assert stat.S_IMODE((tmp_path / "jira-api-token").stat().st_mode) == 0o444


def test_database_url_from_file(tmp_path, monkeypatch):
    from aap.db import database_url

    f = tmp_path / "db"
    f.write_text("postgresql+psycopg://aap_api_login:pw@db/aap\n")
    monkeypatch.delenv("AAP_DATABASE_URL", raising=False)
    monkeypatch.setenv("AAP_DATABASE_URL_FILE", str(f))
    assert database_url() == "postgresql+psycopg://aap_api_login:pw@db/aap"
