# Security Risk Model (finding prioritisation)

| | |
|---|---|
| Status | DESIGNED. Weights, bands and SLAs PROPOSED, REQUIRES HUMAN APPROVAL (Governance Board, CISO for SLAs) |
| Configuration | [`config/risk-model.yaml`](../../config/risk-model.yaml) (authoritative, versioned) |
| Decision records | [ADR-011](../../adr/ADR-011-vulnerability-risk-model.md), [ADR-012](../../adr/ADR-012-cvss-epss-usage.md) |

> **This is a prioritisation model, not an objective measure of risk.** It orders work consistently and explainably using information the organisation actually has. It is reviewed against outcomes quarterly and is expected to change.

## 1. Formula

```
Risk priority score = Likelihood (1–5) × Impact (1–5)          → 1..25 → P1 ≥ 20 · P2 ≥ 12 · P3 ≥ 6 · P4
```

### Likelihood

| Component | Source | Effect |
|---|---|---|
| Base | EPSS percentile band (CVE findings) → else CVSS exploitability → else tool severity | 1–5 |
| CISA KEV listed | CISA KEV feed | +2 |
| Public exploit (not KEV) | Advisory references / intel | +1 |
| Confirmed by DAST or pen test | Finding source | +1 |
| Internet-public exposure | `application.yaml`, verified against cloud inventory | +1 |
| Reachable without authentication | DAST/pen test/CVSS PR:N, when known | +1 |
| Unreachable (reachability analysis with evidence) | Reachability tooling | −2 |
| Development-only dependency | SBOM component scope | −1 |
| Isolated application | Exposure | −1 |

### Impact

| Component | Source | Effect |
|---|---|---|
| Base by tier | Tier 1: 4 · Tier 2: 3 · Tier 3: 2 · Tier 4: 1 | 1–4 |
| Highly confidential data or special-category personal data | Classification | +1 |
| Active secret exposed | Secret validity check | +1 |
| High integrity impact on a privileged integration | CVSS impact + classification | +1 |
| Approved compensating control | Exception record | −1 (max) |

### Overrides (raise only)

KEV-listed + internet-facing → **P1** · active secret → **P1** · malicious package → **P1**.

## 2. Why these factors

| Factor | Rationale | Known limitation |
|---|---|---|
| EPSS | Probability of exploitation activity in the wild; strongly concentrates real-world risk | Global, not contextual; CVE-only; changes daily |
| KEV | Ground truth of active exploitation | Lagging; absence ≠ safety |
| Exposure | Internet-facing apps face continuous scanning | Declared exposure may be wrong (hence verification) |
| Tier / data | Business and citizen impact | Classification quality (risk R-03) |
| Reachability | Removes noise for unused code paths | Tool maturity varies; requires evidence |

Factors **not** used and why: raw CVSS base score alone (context-free) · finding age (rewards neither fixing nor detection) · team (would bias).

## 3. Governance of the model

- Changes are made by PR to `config/risk-model.yaml` with Governance Board approval. The model version is stored with every score.
- Re-scoring after a model change only raises priorities automatically. SLA clocks never extend retroactively.
- Manual override needs a reason and a second approver. The override rate is a KRI for model quality (R-17).
- Quarterly review: distribution of priorities, override reasons, incidents traced to under-prioritised findings.
- Later: evaluate CISA **SSVC** as an alternative or front-end ([ADR-011](../../adr/ADR-011-vulnerability-risk-model.md)).

## 4. Worked examples

| Finding | Likelihood | Impact | Score | Priority |
|---|---|---|---|---|
| log4j-core RCE, KEV, on a Tier 1 internet-public API | base 5 (EPSS ≥ 95th) +2 KEV +1 internet → clamp 5 | 4 (T1) +1 (special-category data) = 5 | 25 | **P1** (also override) |
| Same CVE in a dev-only test dependency of a Tier 3 internal app | 5 +2 −1 dev → 5 | 2 | 10 | P3 |
| SAST high (SQL injection) in a Tier 2 internet-authenticated app, not yet confirmed | base 3 (tool high) | 3 | 9 | P3 → becomes P2 if DAST confirms (+1 → 12) |
| Checkov medium on a Tier 4 internal tool | 2 | 1 | 2 | P4 |
| Active Azure client secret in a Tier 3 repo | base 4 | 2 +1 active secret = 3 | 12 | **P1** (override) |
