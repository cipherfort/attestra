# SPDX-License-Identifier: Apache-2.0
"""AzureBlobStore against Azurite (the Azure Storage emulator). Opt in: AAP_TEST_SERVICES=1 (starts a container)."""

from __future__ import annotations

import os
import subprocess
import time
import uuid

import pytest

from aap.blobstore import AzureBlobStore, BlobIntegrityError

pytestmark = [
    pytest.mark.service,
    pytest.mark.skipif(os.environ.get("AAP_TEST_SERVICES") != "1", reason="set AAP_TEST_SERVICES=1"),
]
# Azurite's published, well-known development account key (not a secret: identical in every Azurite install)
DEV_KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="


@pytest.fixture(scope="module")
def container():
    from azure.storage.blob import BlobServiceClient

    name = f"aap-azurite-{uuid.uuid4().hex[:6]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::10000",
            "mcr.microsoft.com/azure-storage/azurite:3.35.0",
            "azurite-blob",
            "--blobHost",
            "0.0.0.0",
            "--loose",
            "--skipApiVersionCheck",
        ],
        check=True,
        capture_output=True,
    )
    try:
        port = (
            subprocess.run(["docker", "port", name, "10000/tcp"], capture_output=True, text=True, check=True)
            .stdout.splitlines()[0]
            .rsplit(":", 1)[-1]
        )
        conn = (
            f"DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey={DEV_KEY};"
            f"BlobEndpoint=http://127.0.0.1:{port}/devstoreaccount1;"
        )
        svc = BlobServiceClient.from_connection_string(conn)
        for attempt in range(30):
            try:
                c = svc.create_container("evidence")
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)
        yield c
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_write_once_and_rehash(container):
    store = AzureBlobStore(container)
    uri = store.put(b'{"evidence": 1}')
    assert uri.startswith("azblob://sha256/") and store.get(uri) == b'{"evidence": 1}'
    assert store.put(b'{"evidence": 1}') == uri  # idempotent: same content, same address, no overwrite

    digest = uri.rsplit("/", 1)[-1]
    blob = container.get_blob_client(f"sha256/{digest[:2]}/{digest[2:4]}/{digest}")
    blob.upload_blob(b"tampered", overwrite=True)  # what the WORM policy prevents in Azure; here: detected on read
    with pytest.raises(BlobIntegrityError):
        store.get(uri)
    with pytest.raises(BlobIntegrityError):
        store.put(b'{"evidence": 1}')
