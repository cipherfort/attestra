# SPDX-License-Identifier: Apache-2.0
"""Secrets and Azure credentials (ADR-015).

One interface for every integration credential the bootstrap commands create and the connectors read:

* `file`     (development only): one file per secret in `AAP_SECRETS_DIR` (default `~/.aap/secrets`), mode 0600 in a
               0700 directory. Refused when `AAP_ENV=production`, and refused if the permissions are looser.
* `keyvault` (deployed): Azure Key Vault `AAP_KEYVAULT_URL`, reached with the platform's managed identity.

Secret names are kebab-case (Key Vault's alphabet). Values are never logged or put in exceptions.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Protocol

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}$")


class SecretError(RuntimeError):
    pass


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def put(self, name: str, value: str, content_type: str = "text/plain") -> None: ...

    def describe(self) -> str: ...


def _check_name(name: str) -> None:
    if not NAME.match(name):
        raise SecretError(f"invalid secret name {name!r}")


class FileSecretStore:
    def __init__(self, directory: str | Path):
        self.dir = Path(directory).expanduser()

    def _ensure_dir(self) -> None:
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = stat.S_IMODE(self.dir.stat().st_mode)
        if mode & 0o077:
            raise SecretError(f"{self.dir} is accessible to other users (mode {mode:o}); chmod 700 it")

    def get(self, name: str) -> str | None:
        _check_name(name)
        path = self.dir / name
        if not path.exists():
            return None
        self._ensure_dir()
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise SecretError(f"secret file {path} is readable by other users (mode {mode:o}); chmod 600 it")
        return path.read_text()

    def put(self, name: str, value: str, content_type: str = "text/plain") -> None:
        _check_name(name)
        self._ensure_dir()
        path = self.dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value)
        os.chmod(path, 0o600)

    def describe(self) -> str:
        return f"file:{self.dir}"


class KeyVaultSecretStore:
    def __init__(self, vault_url: str, credential: Any | None = None):
        from azure.keyvault.secrets import SecretClient

        self.vault_url = vault_url
        self._client = SecretClient(vault_url=vault_url, credential=credential or azure_credential())

    def get(self, name: str) -> str | None:
        from azure.core.exceptions import ResourceNotFoundError

        _check_name(name)
        try:
            value = self._client.get_secret(name).value
        except ResourceNotFoundError:
            return None
        return value

    def put(self, name: str, value: str, content_type: str = "text/plain") -> None:
        _check_name(name)
        self._client.set_secret(name, value, content_type=content_type, tags={"managed-by": "aap-bootstrap"})

    def describe(self) -> str:
        return f"keyvault:{self.vault_url}"


class MountedSecretStore:
    """Read-only secrets mounted as files by the platform (Kubernetes secret volumes, Docker secrets): one file per
    name. Allowed in production. Refuses files anyone outside the owner/group can read (set defaultMode 0400/0440)."""

    def __init__(self, directory: str | Path):
        self.dir = Path(directory)

    def get(self, name: str) -> str | None:
        _check_name(name)
        path = self.dir / name
        if not path.exists():
            return None
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o007:
            raise SecretError(f"mounted secret {path} is world-accessible (mode {mode:o}); mount it with mode 0400")
        return path.read_text().strip()

    def put(self, name: str, value: str, content_type: str = "text/plain") -> None:
        raise SecretError(f"mounted secrets are read-only: create {name!r} in your secret manager and mount it")

    def describe(self) -> str:
        return f"mounted:{self.dir}"


def secret_store() -> SecretStore:
    backend = os.environ.get("AAP_SECRETS_BACKEND", "file")
    if backend == "mounted":
        return MountedSecretStore(os.environ.get("AAP_SECRETS_DIR", "/var/run/secrets/aap"))
    if backend == "keyvault":
        url = os.environ.get("AAP_KEYVAULT_URL")
        if not url:
            raise SecretError("AAP_SECRETS_BACKEND=keyvault needs AAP_KEYVAULT_URL")
        return KeyVaultSecretStore(url)
    if backend == "file":
        if os.environ.get("AAP_ENV", "development") == "production":
            raise SecretError("the file secret store is not permitted when AAP_ENV=production")
        return FileSecretStore(os.environ.get("AAP_SECRETS_DIR", "~/.aap/secrets"))
    raise SecretError(f"unknown AAP_SECRETS_BACKEND {backend!r}")


def require(store: SecretStore, name: str, hint: str) -> str:
    value = store.get(name)
    if not value:
        raise SecretError(f"secret {name!r} not found in {store.describe()}: {hint}")
    return value


def azure_credential() -> Any:
    """Managed identity when deployed (`AAP_AZURE_CLIENT_ID` = the user-assigned identity); the developer's Azure CLI
    login otherwise. Deliberately not DefaultAzureCredential: it would silently fall through to environment secrets."""
    from azure.identity import AzureCliCredential, ManagedIdentityCredential

    client_id = os.environ.get("AAP_AZURE_CLIENT_ID")
    if client_id:
        return ManagedIdentityCredential(client_id=client_id)
    if os.environ.get("AAP_ENV", "development") == "production":
        raise SecretError("AAP_AZURE_CLIENT_ID (managed identity) is required when AAP_ENV=production")
    return AzureCliCredential()
