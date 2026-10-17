# SPDX-License-Identifier: Apache-2.0
"""Content-addressed, write-once evidence storage (ADR-007, ADR-016).

`AzureBlobStore` (deployed): one container with a version-level immutability (WORM) policy created by
examples/terraform/azure/modules/platform, reached over a private endpoint with the platform's managed identity.
Writes are
conditional (`If-None-Match: *`), so even without the policy an existing object is never replaced; reads re-hash.
`LocalBlobStore` (development): same addressing (`sha256/<aa>/<bb>/<digest>`) and write-once semantics on disk.
Azurite (deploy/local) exercises the Azure code path locally; it does not enforce immutability policies, so the
storage-level WORM guarantee is verified only in Azure (examples/terraform/azure/README.md, post-deploy checks).
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Protocol


class BlobIntegrityError(RuntimeError):
    pass


class EvidenceBlobStore(Protocol):
    def put(self, data: bytes) -> str: ...

    def get(self, uri: str) -> bytes: ...


class LocalBlobStore:
    scheme = "local"

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        return self.root / "sha256" / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        path = self._path(digest)
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise BlobIntegrityError(f"stored object {digest} does not match its address")
            return self.uri(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IRGRP)  # read-only: write-once semantics
        tmp.rename(path)
        return self.uri(digest)

    def uri(self, digest: str) -> str:
        return f"{self.scheme}://sha256/{digest}"

    def get(self, uri: str) -> bytes:
        digest = uri.rsplit("/", 1)[-1]
        data = self._path(digest).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise BlobIntegrityError(f"object {digest} failed re-hash")
        return data


class AzureBlobStore:
    scheme = "azblob"

    def __init__(self, container_client: Any):
        self._c = container_client

    @staticmethod
    def _name(digest: str) -> str:
        return f"sha256/{digest[:2]}/{digest[2:4]}/{digest}"

    def put(self, data: bytes) -> str:
        from azure.core import MatchConditions
        from azure.core.exceptions import ResourceExistsError

        digest = hashlib.sha256(data).hexdigest()
        blob = self._c.get_blob_client(self._name(digest))
        try:
            blob.upload_blob(
                data, overwrite=False, metadata={"sha256": digest}, match_condition=MatchConditions.IfMissing
            )
        except ResourceExistsError:
            existing = blob.download_blob().readall()
            if hashlib.sha256(existing).hexdigest() != digest:
                raise BlobIntegrityError(f"stored object {digest} does not match its address") from None
        return f"{self.scheme}://sha256/{digest}"

    def get(self, uri: str) -> bytes:
        digest = uri.rsplit("/", 1)[-1]
        data: bytes = self._c.get_blob_client(self._name(digest)).download_blob().readall()
        if hashlib.sha256(data).hexdigest() != digest:
            raise BlobIntegrityError(f"object {digest} failed re-hash")
        return data


class S3BlobStore:
    """S3-compatible storage (AWS S3, MinIO, Ceph, ...). WORM = a bucket created with Object Lock and a default
    retention in COMPLIANCE mode (Helm chart / Terraform examples); `worm_status()` reports what the bucket enforces.
    Writes are conditional (`If-None-Match: *`): an existing object is never replaced through this store."""

    scheme = "s3"

    def __init__(self, client: Any, bucket: str, prefix: str = ""):
        self._c, self.bucket, self.prefix = client, bucket, prefix.strip("/")

    def _key(self, digest: str) -> str:
        key = f"sha256/{digest[:2]}/{digest[2:4]}/{digest}"
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, data: bytes) -> str:
        from botocore.exceptions import ClientError

        digest = hashlib.sha256(data).hexdigest()
        try:
            self._c.put_object(
                Bucket=self.bucket,
                Key=self._key(digest),
                Body=data,
                IfNoneMatch="*",
                ChecksumAlgorithm="SHA256",
                Metadata={"sha256": digest},
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise
            if hashlib.sha256(self._read(digest)).hexdigest() != digest:
                raise BlobIntegrityError(f"stored object {digest} does not match its address") from None
        return f"{self.scheme}://sha256/{digest}"

    def _read(self, digest: str) -> bytes:
        body: bytes = self._c.get_object(Bucket=self.bucket, Key=self._key(digest))["Body"].read()
        return body

    def get(self, uri: str) -> bytes:
        digest = uri.rsplit("/", 1)[-1]
        data = self._read(digest)
        if hashlib.sha256(data).hexdigest() != digest:
            raise BlobIntegrityError(f"object {digest} failed re-hash")
        return data

    def worm_status(self) -> dict[str, Any]:
        from botocore.exceptions import ClientError

        try:
            cfg = self._c.get_object_lock_configuration(Bucket=self.bucket)["ObjectLockConfiguration"]
        except ClientError:
            return {"object_lock": False}
        rule = (cfg.get("Rule") or {}).get("DefaultRetention") or {}
        return {
            "object_lock": cfg.get("ObjectLockEnabled") == "Enabled",
            "mode": rule.get("Mode"),
            "days": rule.get("Days") or None,
            "years": rule.get("Years") or None,
        }


def default_store() -> EvidenceBlobStore:
    """AAP_BLOB_KIND (local | azure | s3), else inferred: AAP_BLOB_S3_BUCKET → S3 (default AWS credential chain:
    workload identity / instance role; AAP_BLOB_S3_ENDPOINT for MinIO and other S3-compatible stores);
    AAP_BLOB_ACCOUNT_URL → Azure (managed identity); AAP_BLOB_CONNECTION_STRING → Azurite (development only);
    otherwise the local directory AAP_BLOB_ROOT (development only)."""
    kind = os.environ.get("AAP_BLOB_KIND") or (
        "s3"
        if os.environ.get("AAP_BLOB_S3_BUCKET")
        else "azure"
        if os.environ.get("AAP_BLOB_ACCOUNT_URL") or os.environ.get("AAP_BLOB_CONNECTION_STRING")
        else "local"
    )
    container = os.environ.get("AAP_BLOB_CONTAINER", "evidence")
    production = os.environ.get("AAP_ENV") == "production"
    if kind == "s3":
        import boto3

        client = boto3.client(
            "s3",
            endpoint_url=os.environ.get("AAP_BLOB_S3_ENDPOINT") or None,
            region_name=os.environ.get("AAP_BLOB_S3_REGION") or None,
        )
        return S3BlobStore(client, os.environ["AAP_BLOB_S3_BUCKET"], os.environ.get("AAP_BLOB_S3_PREFIX", ""))
    if kind == "azure" and os.environ.get("AAP_BLOB_ACCOUNT_URL"):
        from azure.storage.blob import ContainerClient

        from aap.secrets import azure_credential

        return AzureBlobStore(
            ContainerClient(os.environ["AAP_BLOB_ACCOUNT_URL"], container, credential=azure_credential())
        )
    if kind == "azure" and os.environ.get("AAP_BLOB_CONNECTION_STRING"):
        if production:
            raise RuntimeError("connection-string blob access is not permitted in production; use the managed identity")
        from azure.storage.blob import ContainerClient

        return AzureBlobStore(
            ContainerClient.from_connection_string(os.environ["AAP_BLOB_CONNECTION_STRING"], container)
        )
    if kind == "azure":
        raise RuntimeError("AAP_BLOB_KIND=azure needs AAP_BLOB_ACCOUNT_URL")
    if production:
        raise RuntimeError("production needs WORM evidence storage: set AAP_BLOB_S3_BUCKET or AAP_BLOB_ACCOUNT_URL")
    return LocalBlobStore(os.environ.get("AAP_BLOB_ROOT", ".aap-blobs"))
