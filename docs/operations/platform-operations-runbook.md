# Platform operations runbook

| | |
|---|---|
| Applies to | Deployments from the [Helm chart](../../charts/fortproof/README.md) or the [Compose stack](../../deploy/compose/README.md) |
| Related | [Backup and restore](backup-and-restore-plan.md) · [Disaster recovery](disaster-recovery-plan.md) · [Incident response](../runbooks/incident-response.md) · [Key rotation](../runbooks/key-rotation.md) |

## 1. What runs

| Process | Command | Does | Health |
|---|---|---|---|
| API | `aap api` | REST API, sign-in, serves the web UI | `GET /api/v1/health/live`, `GET /api/v1/health/ready` (checks the database) |
| Webhook receiver | `aap hook` | Verifies GitHub and GitLab webhook signatures, records the delivery, queues a job | The only process that needs to be reachable from the internet |
| Worker | `aap worker` | Claims jobs from the PostgreSQL queue: `ingest`, `onboarding`, `assessment`, `evaluate`, `scheduler`, `snapshot`, `connector`, `github-sync` | Job age and dead jobs (section 3) |
| Migration job | `aap migrate`, `aap config load`, `aap db provision-logins` | Runs before each install and upgrade | Exit code; the chart stops the upgrade if it fails |

Each process connects with its own database login, so a compromised API cannot write evidence. Evidence files go to
write-once object storage (S3 with Object Lock, or Azure Blob with an immutability policy).

**The scheduler sweep** runs every 5 minutes by default (`worker.scheduler_interval`; one sweep at a time, however many
workers run): it queues connector runs that are due, marks findings past their deadline,
expires exceptions, re-evaluates every classified application, refreshes the current month's snapshot, and verifies
the current month's evidence hash chain. A broken chain logs a critical error and raises the
`evidence.integrity_failure` event ([evidence integrity runbook](../runbooks/evidence-integrity-mismatch.md)).

## 2. Routine operations

| Task | When | How |
|---|---|---|
| Integration health | Daily | **Integrations** page, or `aap integrations status`: what is configured, what is missing, last run and what it could not read. Re-run one now: `aap integrations run <key>` |
| Dead jobs | Daily | `SELECT queue, count(*) FROM jobs WHERE status = 'dead' GROUP BY queue;` then read `last_error`. Fix the cause; a dead job is re-queued by the next event or sweep for the same application |
| Rejected evidence | Daily | **Evidence → Rejected**. A spike after a security-workflows release usually means the new commit is not approved yet (`UNAPPROVED_WORKFLOW_REF`) |
| Trusted producer update | Each security-workflows release | `aap pipelines approve --repository <org>/security-workflows --sha <commit> --release <tag>`, then merge the change to `config/trusted-producers.yaml` by pull request |
| Rules change (catalogue, config) | Each merged pull request | Deploy; the migration job runs `aap config load`, and every evaluation records the rule version it used |
| Settings check | Each change to `aap.yaml` | `aap settings check aap.yaml` |
| Credential rotation | Per schedule | [Key rotation runbook](../runbooks/key-rotation.md) |
| Access review | Quarterly | **Admin → Role grants**: export and review organization-wide roles |
| Restore drill | Every 6 months | [Backup and restore section 3](backup-and-restore-plan.md#3-restore-drill) |
| Image and dependency updates | Weekly | Renovate or Dependabot pull requests; releases are signed (verify before deploying, below) |

## 3. Deploy and upgrade

1. Verify the release before deploying: `cosign verify` on the image and chart, and `gh attestation verify` for the
   build provenance (commands in each release's notes).
2. `helm upgrade` (or `docker compose pull && docker compose up -d`). The migration job runs first. Migrations are
   forward-only, and each release upgrades from the previous minor release.
3. Smoke test: `/api/v1/health/ready` returns 200, sign in, open the Overview and Integrations pages.
4. Roll back by deploying the previous image when the release had no database migration (its notes say so).
   Migrations are forward-only: to undo one, restore the database from before the upgrade
   ([backup plan, section 2](backup-and-restore-plan.md#2-restore)).

## 4. Common problems

| Symptom | Likely cause | Action |
|---|---|---|
| Webhook deliveries failing | Receiver not reachable, or a wrong webhook secret | Check the delivery log in the GitHub App or GitLab group settings; check `aap hook` logs. Missed deliveries are picked up by the next scheduled connector run |
| GitHub rate limiting (403/429 in connector runs) | Too many repositories synced at once | Lengthen the interval in `config/integrations.yaml`. Never switch to a personal token |
| Integration shows *Last run failed* | Expired credential, blocked egress, or the upstream is down | Read the error on the Integrations page; fix it, then `aap integrations run <key>` |
| Controls show *No evidence* after a pipeline run | Evidence rejected, or the run was not on the default branch | **Evidence → Rejected** for that repository; check the workflow commit is approved |
| Jobs piling up | Worker down, or one slow handler | Check the worker is running and its logs; run more worker replicas (`worker.replicas` in the chart) |
| `evidence.integrity_failure` | Hash chain mismatch | P1: [evidence integrity runbook](../runbooks/evidence-integrity-mismatch.md) |

## 5. Escalation

Platform operator → the AppSec lead. Security incidents: [incident response runbook](../runbooks/incident-response.md).
