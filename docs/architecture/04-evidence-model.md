# 04 — Evidence Model and Freshness Engine

| | |
|---|---|
| Status | DESIGNED |
| Related | [ADR-004](../../adr/ADR-004-evidence-driven-security-model.md), [ADR-007](../../adr/ADR-007-evidence-storage-architecture.md), [ADR-016](../../adr/ADR-016-evidence-immutability.md), [ADR-017](../../adr/ADR-017-evidence-retention.md), [`config/evidence-types.yaml`](../../config/evidence-types.yaml), [`schemas/evidence/evidence-manifest.schema.json`](../../schemas/evidence/evidence-manifest.schema.json) |

## 1. Principles

1. **Evidence is an observation, not a claim.** It records *who observed what, about which exact thing (commit, digest, setting), when, with which tool and version*.
2. **The platform collects evidence; it does not accept assertions.** Pipeline evidence is pulled from GitHub and verified ([§4](#4-producer-verification)). Configuration evidence is read from authoritative APIs. Only manual evidence is entered by people, and it carries their identity and an SoD check.
3. **Evidence is immutable.** Corrections are new records (revocation, supersession), never edits.
4. **Evidence expires.** Freshness is computed, not assumed. Expired evidence is retained but no longer satisfies controls.
5. **Every claim is traceable** from dashboard number → control state → evaluation → evidence IDs → raw artefact SHA-256 in WORM storage.

## 2. Evidence record

| Field | Type | Notes |
|---|---|---|
| `evidence_id` | UUIDv7 | Time-ordered; external display `EV-<base32>` |
| `evidence_type` | text | Registry key, e.g. `scan.sast` |
| `application_id` | UUID | Resolved at ingestion from repo → app links (nullable for org-level evidence) |
| `scope_type` / `scope_ref` | enum / text | `repository` + repo node ID · `artifact` + digest · `cloud_scope` · `organisation` |
| `subject` | jsonb | What was observed: `{repo, ref, commit_sha}` or `{artifact_digest, artifact_name}` or `{setting_path}` |
| `producer_type` | enum | `approved_workflow` · `platform_connector` · `manual` · `external_system` |
| `producer_ref` | text | e.g. `example-org/security-workflows/.github/workflows/sast.yml@<sha>`, `connector:github@1.4.2`, `user:<entra-oid>` |
| `tool` / `tool_version` | text | e.g. `codeql` / `2.19.1`; `trivy` / `0.56.2` |
| `policy_ref` | text | Ruleset or policy version, e.g. `codeql-suite:security-extended@<pack-version>` |
| `observed_at` | timestamptz | When the observation occurred (tool run end) |
| `ingested_at` | timestamptz | When the platform recorded it |
| `result` | enum | `pass` · `fail` · `findings` · `inconclusive` · `error` · `observed` (for config snapshots) |
| `summary` | jsonb | Normalised summary (counts by severity, languages covered, URLs crawled, settings values) |
| `confidence` | enum | `C0`–`C3`, `M1`, `M2` (§3) |
| `confidence_reasons` | text[] | e.g. `["approved_workflow_verified","attestation_verified","non_ephemeral_runner"]` |
| `run_ref` | jsonb | `{run_id, run_attempt, workflow_ref, event, actor, runner_environment}` |
| `raw_location` | text | Blob URI (platform-generated) |
| `raw_sha256` | bytea[] | Digests of raw files |
| `attestation_ref` | text | Attestation bundle digest (Sigstore) if present |
| `valid_from` / `valid_until_hint` | timestamptz | Initial freshness computation. The authoritative state is the freshness engine's (§5). |
| `prev_hash` / `record_hash` | bytea | Hash chain (§6) |

The canonical JSON form of a record (RFC 8785 JCS) is what is hashed.

## 3. Confidence levels

| Level | Name | Definition | Example | Can satisfy |
|---|---|---|---|---|
| **C0** | Declared | A team claim in `.security/*.yaml` or a form, with no observation | `sast: enabled: true` in a YAML file | **Nothing** (informational only) |
| **C1** | Configured | The platform observed a setting via an authoritative API | Ruleset requires 2 approvals; workflow file exists | Configuration controls only |
| **C2** | Executed | The platform verified an approved workflow ran on a specific commit/digest and produced a result | `sast.yml@sha` run 123 on commit abc, CodeQL 2.19.1, 3 languages | Activity controls |
| **C3** | Attested / authoritative | C2 + verified Sigstore attestation and hash-matched raw output, **or** data pulled directly by the platform from the system of record | GHAS code-scanning analyses API; secret-scanning alerts API | All automated controls |
| **M1** | Manual, self | Recorded by the owning team with artefacts | Team records threat-model review | Manual controls where policy allows |
| **M2** | Manual, independent | Recorded or approved by someone outside the team; SoD enforced | AppSec architecture review sign-off | All manual controls |

Downgrade rules (applied automatically, recorded in `confidence_reasons`): evidence from a non-ephemeral self-hosted runner is capped at C2 (threat T-03); evidence whose tool version is on the revocation list is invalid; evidence produced on a non-default branch can satisfy only PR-scoped controls.

> **Invariant:** *"The platform must never claim a control is satisfied because a repository contains a configuration file."* A workflow file present in the repo is **C1**. Every activity control requires **≥ C2**, and `tools/catalogue/validate.py` enforces that no control's minimum confidence is unreachable from its evidence types.

## 4. Producer verification

The **trusted producer registry** (`config/trusted-producers.yaml`, E08) lists:

```yaml
workflows:
  - path: example-org/security-workflows/.github/workflows/sast.yml
    evidence_types: [scan.sast]
    approved_shas: [<sha of v1.3.0>, <sha of v1.4.0>]   # release process appends; old SHAs retire after 90 days
connectors:
  - id: github
    evidence_types: [repo.ruleset, repo.security_settings, ...]
```

Verification steps for workflow evidence (all must pass, otherwise the evidence is **rejected** with a reason code and an audit event):

1. **Run exists and completed:** GET the workflow run via the GitHub App. `conclusion ∈ {success, failure}`. A failed *scan step* is still evidence, with result `error`.
2. **Approved caller:** the run's `referenced_workflows[]` contains an approved `path@sha` for the evidence type → otherwise `UNAPPROVED_WORKFLOW_REF`.
3. **Attestation:** the artifact's attestation verifies (Sigstore bundle), and its certificate's *Build Signer URI* equals the approved workflow `path@ref`, with the matching source repository → otherwise `ATTESTATION_INVALID`. Until artifact attestations are confirmed for the org (assumption A-05), steps 1–2 alone give C2.
4. **Integrity:** the manifest's `subject` digests equal the SHA-256 of downloaded raw files → otherwise `DIGEST_MISMATCH`.
5. **Binding:** manifest `commit_sha` equals the run's `head_sha`, and the manifest repo equals the webhook's repository ID → otherwise `BINDING_MISMATCH`.
6. **Limits:** size, file count and decompression ratio are within limits → otherwise `REJECTED_SIZE`.

## 5. Freshness engine

### 5.1 Policies

Configured per evidence type ([`config/evidence-types.yaml`](../../config/evidence-types.yaml)) and overridable per control.

| Policy | Valid while | Expires when | Typical types |
|---|---|---|---|
| `continuous` | Last poll within `ttl` | Poll gap > ttl (connector failure surfaces as `STALE`, not silently "fine") | Repo settings, GHAS alerts, cloud posture |
| `commit_bound` | Evidence commit is the default-branch HEAD, **or** every commit since touches none of `paths` | A *meaningful change* lands, or `ceiling_days` passes | SAST, SCA, IaC, workflow lint |
| `artifact_bound` | Evidence digest is the current build / a currently deployed digest | A new digest is deployed/built and lacks evidence, or `ceiling_days` passes | SBOM, container scan, provenance |
| `time_bound` | `observed_at + valid_days` | Time | Pen test, training, manual attestations |
| `event_bound` | No invalidating event since `observed_at` | An event in `invalidated_by`, or `ceiling_days` | Threat model, architecture review, DAST |

### 5.2 Meaningful change (commit_bound)

```
on push to default branch (webhook) for repo R, new HEAD H:
  for each commit_bound evidence E on R with E.commit = C:
      changed = GitHub compare(C...H).files              # cached per (C,H)
      if any(fnmatch(f, E.type.paths) for f in changed):
          supersede E at H  (state SUPERSEDED, reason "meaningful change: <first 5 paths>")
      else:
          E remains valid for H (recorded as an evidence_validity_event so the chain of reasoning is auditable)
```

The compare result is truncated by GitHub above 300 files. Truncation is treated as a meaningful change (fail safe).

### 5.3 Derived state

Evidence rows are immutable. Freshness state lives in `evidence_validity_events` (append-only) and the current projection `evidence_current_state`:

`ACTIVE → EXPIRING (warn_days) → EXPIRED` · `ACTIVE → SUPERSEDED` · `ANY → REVOKED`

**Revocation.** If a tool version is later found defective (e.g. a scanner release that silently skipped a language), a revocation rule (`tool = X and tool_version in [...]`) marks matching evidence REVOKED, triggers re-evaluation of affected controls, and notifies owners. Integrity incidents (such as the trivy-action tag compromise) use the same mechanism to invalidate evidence from a compromised window.

### 5.4 Scheduler

An hourly sweep transitions time-based states and enqueues control re-evaluation. A daily job emits "expiring in N days" notifications to owners (batched digest, not per item).

## 6. Immutability and audit (summary of ADR-016)

```
Raw artefacts ──▶ Blob container  evidence-raw   (version-level immutability, time-based retention, locked)
                   path: sha256/<aa>/<bb>/<digest>   (content-addressed; dedups identical uploads)
Manifest      ──▶ Blob            evidence-manifests/<yyyy>/<mm>/<evidence_id>.json  (immutable)
Record        ──▶ PostgreSQL      evidence (partitioned monthly; INSERT-only grant; UPDATE/DELETE trigger raises)
Chain         ──▶ record_hash = SHA-256( prev_hash ‖ JCS(record without hash fields) )   per partition
Checkpoint    ──▶ daily: {partition, last_record_hash, count, generated_at} → Blob evidence-checkpoints (immutable)
                   + emitted to Sentinel as an audit event (an external copy outside the platform's control)
Verification  ──▶ daily recompute of the chain + 1% random blob re-hash; mismatch = P1 platform incident
```

## 7. Manual evidence

Manual evidence (threat-model review, architecture review, pen test, SAMM interview, manual control attestation) is recorded through a form that captures: scope; method; outcome; reviewer (from the session, never typed); a reference to version-controlled artefacts (commit SHA of `.security/threat-model/**`) or uploaded attachments (stored in WORM with a hash); and requirement or control IDs covered. **M2** requires the reviewer not to be in the application's owning team (checked against `application.yaml` owners + GitHub team membership + Entra group). Self-review attempts are rejected and audited.

## 8. Example: pipeline SAST evidence (normalised record)

```json
{
  "evidence_id": "0192f1a8-7c3e-7b21-9f00-3c1b7a5e2d10",
  "evidence_type": "scan.sast",
  "application_id": "6f1c…",
  "scope_type": "repository",
  "scope_ref": "R_kgDOJx…",
  "subject": { "repo": "example-org/claims-api", "ref": "refs/heads/main", "commit_sha": "3f2a9c…" },
  "producer_type": "approved_workflow",
  "producer_ref": "example-org/security-workflows/.github/workflows/sast.yml@8d1e…",
  "tool": "codeql", "tool_version": "2.19.1",
  "policy_ref": "codeql-suite:security-extended",
  "observed_at": "2026-10-07T10:14:22Z",
  "result": "findings",
  "summary": { "languages": ["java", "javascript"], "languages_detected": ["java", "javascript"], "alerts": { "critical": 0, "high": 2, "medium": 5 } },
  "confidence": "C3",
  "confidence_reasons": ["approved_workflow_verified", "attestation_verified", "github_hosted_runner"],
  "run_ref": { "run_id": 11223344, "run_attempt": 1, "event": "push", "runner_environment": "github-hosted" },
  "raw_location": "https://<acct>.blob.core.windows.net/evidence-raw/sha256/ab/cd/abcd…",
  "raw_sha256": ["abcd…"],
  "attestation_ref": "sha256:9e1f…"
}
```
