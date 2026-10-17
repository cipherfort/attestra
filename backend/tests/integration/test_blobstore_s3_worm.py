# SPDX-License-Identifier: Apache-2.0
"""S3BlobStore against a real S3-compatible server with Object Lock in COMPLIANCE mode: the WORM guarantee the emulators
can't show. Opt in: AAP_TEST_SERVICES=1 (starts a container).

Default server: RustFS (Apache-2.0). MinIO no longer publishes its server image; with access to one, run
AAP_TEST_S3_SERVER=minio AAP_TEST_S3_IMAGE=<your minio image>."""

from __future__ import annotations

import os
import subprocess
import time
import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from aap.blobstore import BlobIntegrityError, S3BlobStore

RUSTFS = "rustfs/rustfs:1.0.1@sha256:1803faef57627e2d9c2e7d89d655d712ddded5389040054987163043fecb6a3c"

pytestmark = [
    pytest.mark.service,
    pytest.mark.skipif(os.environ.get("AAP_TEST_SERVICES") != "1", reason="set AAP_TEST_SERVICES=1"),
]


@pytest.fixture(scope="module")
def s3():
    server = os.environ.get("AAP_TEST_S3_SERVER", "rustfs")
    name = f"aap-s3-{uuid.uuid4().hex[:6]}"
    user, password = "aaptest", uuid.uuid4().hex
    if server == "minio":
        env, image, cmd = (
            ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"],
            os.environ["AAP_TEST_S3_IMAGE"],
            ["server", "/data"],
        )
    else:
        env, cmd = ["RUSTFS_ACCESS_KEY", "RUSTFS_SECRET_KEY"], ["/data"]
        image = os.environ.get("AAP_TEST_S3_IMAGE", RUSTFS)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::9000",
            "-e",
            f"{env[0]}={user}",
            "-e",
            f"{env[1]}={password}",
            image,
            *cmd,
        ],
        check=True,
        capture_output=True,
    )
    try:
        port = (
            subprocess.run(["docker", "port", name, "9000/tcp"], capture_output=True, text=True, check=True)
            .stdout.splitlines()[0]
            .rsplit(":", 1)[-1]
        )
        client = boto3.client(
            "s3",
            endpoint_url=f"http://127.0.0.1:{port}",
            aws_access_key_id=user,
            aws_secret_access_key=password,
            region_name="us-east-1",
            config=Config(s3={"addressing_style": "path"}),
        )
        for _ in range(60):
            try:
                client.list_buckets()
                break
            except Exception:
                time.sleep(1)
        client.create_bucket(Bucket="aap-evidence", ObjectLockEnabledForBucket=True)
        client.put_object_lock_configuration(
            Bucket="aap-evidence",
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 1}},
            },
        )
        yield client
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_compliance_mode_worm(s3):
    store = S3BlobStore(s3, "aap-evidence")
    assert store.worm_status()["mode"] == "COMPLIANCE"
    uri = store.put(b"signed evidence bundle")
    assert store.put(b"signed evidence bundle") == uri  # conditional write: existing object kept
    digest = uri.rsplit("/", 1)[-1]
    key = f"sha256/{digest[:2]}/{digest[2:4]}/{digest}"
    version = s3.head_object(Bucket="aap-evidence", Key=key)["VersionId"]
    with pytest.raises(ClientError):  # the locked version cannot be deleted, even by the root user
        s3.delete_object(Bucket="aap-evidence", Key=key, VersionId=version)
    s3.put_object(Bucket="aap-evidence", Key=key, Body=b"forged")  # a new version written around the store...
    with pytest.raises(BlobIntegrityError):  # ...is detected on read; the original version is still retained
        store.get(uri)
    original = s3.get_object(Bucket="aap-evidence", Key=key, VersionId=version)["Body"].read()
    assert original == b"signed evidence bundle"
