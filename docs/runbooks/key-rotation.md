# Key and secret rotation runbook

| | |
|---|---|
| Related | [ADR-015](../../adr/ADR-015-secrets-management.md) · [ADR-005](../../adr/ADR-005-github-primary-source-integration.md) · [Reference deployment on Azure](../operations/integration-bootstrap.md) |
| Principle | Where the upstream system allows two credentials at once, make the new one live before revoking the old. Record every rotation as a change. |

Secrets are stored with `aap secrets put <name>` (value from a hidden prompt or standard input) in the deployment's
secret store: Kubernetes secrets or a mounted CSI store, or Azure Key Vault. The processes read them at start-up, so
restart after a change (`kubectl rollout restart deploy`, or restart the Compose services).

| Secret | Suggested schedule | Procedure |
|---|---|---|
| `github-app-private-key` | 90 days, or at once on suspicion | Generate a new key in the GitHub App settings (GitHub allows several active keys) → `aap secrets put github-app-private-key` → restart → confirm the next GitHub connector run succeeds → delete the old key in GitHub. On Azure the key can live in Key Vault as a non-exportable key instead: `aap bootstrap github-app-key-to-keyvault` |
| `github-webhook-secret`, `gitlab-webhook-secret` | 180 days | The receiver checks one secret, so plan a short window: set the new value in the secret store and restart the receiver, then immediately set it in the GitHub App (or GitLab group hook) settings. Deliveries in between fail and are picked up by the next connector run |
| `gitlab-token`, `gitlab-issues-token` | Before the token's expiry (GitLab enforces one) | `aap bootstrap gitlab` creates a fresh read-only group token; store it, restart, then revoke the old token in GitLab |
| `jira-api-token` | 90 days | Create a new token for the service account → `aap secrets put jira-api-token` → restart → confirm a sync → revoke the old token |
| `dependency-track-api-key` | 90 days | Add a new key to the platform's team in Dependency-Track → store it → restart → confirm a sync → delete the old key |
| `defectdojo-api-token` | 90 days | Regenerating in DefectDojo invalidates the old token at once: store the new one straight away and restart, off-peak |
| `siem-http-token`, `notify-webhook-url` | Per your SIEM or chat tool's policy | Create the new token or webhook → store it → restart → confirm the next event arrives → revoke the old one |
| `oidc-client-secret` | Per your identity provider's policy | Add a second client secret in the identity provider → store it → restart → confirm sign-in → remove the old secret |
| Database logins (`database-url-*`) | Yearly, or on suspicion | Change the values in the secret, then `helm upgrade`: the migration job sets the new passwords (`aap db provision-logins`). Restart the processes |
| Cloud access (AWS, Azure) | No secret | Federated identity (IRSA, Azure workload identity): review the role assignments quarterly |

**Emergency rotation:** when a credential may be compromised, revoke it first and accept the outage, then create and
store the new one, and open an incident ([incident response](incident-response.md)).

**Repository-held scanner keys:** if application repositories held Dependency-Track or DefectDojo keys before the
shipped pipelines replaced them, delete those repository secrets **and** revoke the keys. Rotating alone is not
enough, because everyone who could write to those repositories could read them.
