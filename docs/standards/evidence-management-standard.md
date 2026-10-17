# Evidence Management Standard

| | |
|---|---|
| ID | STD-11 · Status: DRAFT, REQUIRES HUMAN APPROVAL |
| Owner | Head of Application Security. Platform team operates. |
| Related | [Evidence model](../architecture/04-evidence-model.md), [ADR-004](../../adr/ADR-004-evidence-driven-security-model.md), [ADR-016](../../adr/ADR-016-evidence-immutability.md), [ADR-017](../../adr/ADR-017-evidence-retention.md), [Data Retention Policy](../../adoption-kit/governance/data-retention-policy.md) |

## 1. Purpose

Defines what counts as security evidence, how it is produced, verified, stored, aged and retained, so that every important security claim can be backed by evidence.

## 2. Requirements

| ID | Requirement |
|---|---|
| EVM-01 | Every control in the catalogue shall define its evidence types, minimum confidence and proof statement. The catalogue validator enforces it. |
| EVM-02 | Evidence shall carry: type, application, scope, subject (commit/digest/setting), producer, tool and version, policy, observation time, result, confidence, raw-artefact hashes, and the run reference where applicable |
| EVM-03 | **Declared information (C0) never satisfies a control. Configuration presence (C1) never satisfies an activity control.** |
| EVM-04 | Pipeline evidence is accepted only from trusted producers ([`config/trusted-producers.yaml`](../../config/trusted-producers.yaml)) after verification of workflow identity, attestation, digests and commit binding |
| EVM-05 | Manual evidence records the reviewer from their authenticated session. M2 requires a reviewer outside the owning team. Attachments are malware-scanned and hashed. |
| EVM-06 | Evidence records and raw artefacts are immutable. Corrections are made by revocation or supersession records. |
| EVM-07 | Evidence freshness is computed by the freshness engine per evidence type ([`config/evidence-types.yaml`](../../config/evidence-types.yaml)). Expired evidence does not satisfy controls. |
| EVM-08 | Evidence integrity (hash chain, blob hashes) is verified daily. Failures are P1 platform incidents. |
| EVM-09 | Evidence is retained per the Data Retention Policy. WORM retention is not locked until that policy is approved. |
| EVM-10 | Evidence for public repositories is internal and never published with the source |
| EVM-11 | Evidence may be revoked by AppSec (for example, a defective tool version or a compromised producer). Revocations are audited and trigger re-evaluation. |
| EVM-12 | Access to raw artefacts is role-scoped, via short-lived single-blob links, and audited |

## 3. Confidence levels

C0 declared · C1 configured · C2 executed · C3 attested/authoritative · M1 manual-self · M2 manual-independent ([definitions](../architecture/04-evidence-model.md#3-confidence-levels)).

## 4. Audit use

Auditors receive time-bound `auditor` role access and can traverse: control state → evaluation → evidence → raw artefact → hash → daily checkpoint (also present in Sentinel).
