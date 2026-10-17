# SPDX-License-Identifier: Apache-2.0
"""Every queue the webhook receiver can enqueue has a worker handler, and the worker polls it (no orphaned jobs)."""

from aap.config import ConfigBundle
from aap.hook.app import jobs_for
from aap.worker.runner import Worker


def test_every_hook_queue_is_handled_and_polled(tmp_path, monkeypatch):
    monkeypatch.setenv("AAP_BLOB_ROOT", str(tmp_path))
    w = Worker(engine=None, bundle=ConfigBundle.load())  # type: ignore[arg-type]
    repo = {"repository": {"id": 1, "full_name": "acme/app"}}
    events = [
        ("workflow_run", {**repo, "action": "completed", "workflow_run": {"id": 9}}),
        ("push", repo),
        ("repository_ruleset", repo),
        ("secret_scanning_alert", repo),
        ("code_scanning_alert", repo),
    ]
    queues = {q for e, payload in events for q, _, _ in jobs_for(e, payload)}
    assert queues, "the receiver should enqueue something"
    polled = Worker.run_once.__defaults__[0]
    for q in queues:
        assert q in w.handlers, f"no handler for queue {q!r}"
        assert q in polled, f"worker never polls queue {q!r}"
