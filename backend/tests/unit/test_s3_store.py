# SPDX-License-Identifier: Apache-2.0
"""S3BlobStore against moto: conditional writes, re-hash on read, WORM status from the bucket's Object Lock."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from aap.blobstore import BlobIntegrityError, S3BlobStore


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="eu-west-1")
        client.create_bucket(
            Bucket="aap-evidence",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
            ObjectLockEnabledForBucket=True,
        )
        client.put_object_lock_configuration(
            Bucket="aap-evidence",
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2555}},
            },
        )
        yield client


def test_write_once_and_rehash(s3):
    store = S3BlobStore(s3, "aap-evidence", prefix="acme")
    uri = store.put(b"evidence")
    assert uri.startswith("s3://sha256/") and store.get(uri) == b"evidence"
    assert store.put(b"evidence") == uri  # same content: idempotent
    key = "acme/sha256/" + uri.rsplit("/", 1)[-1][:2] + "/" + uri.rsplit("/", 1)[-1][2:4] + "/" + uri.rsplit("/", 1)[-1]
    s3.put_object(Bucket="aap-evidence", Key=key, Body=b"tampered")  # a new version, written around the store
    with pytest.raises(BlobIntegrityError):
        store.get(uri)


def test_worm_status_reports_the_bucket_policy(s3):
    assert S3BlobStore(s3, "aap-evidence").worm_status() == {
        "object_lock": True,
        "mode": "COMPLIANCE",
        "days": 2555,
        "years": None,
    }
    s3.create_bucket(Bucket="plain-bucket", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    assert S3BlobStore(s3, "plain-bucket").worm_status() == {"object_lock": False}
