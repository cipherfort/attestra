# Key and Secret Rotation Runbook

| | |
|---|---|
| Related | [ADR-015](../../adr/ADR-015-secrets-management.md), [ADR-005](../../adr/ADR-005-github-primary-source-integration.md) |
| Principle | Rotate with overlap (new credential live before the old one is revoked). Every rotation is recorded as an audited change. |

| Credential | Schedule | Where | Procedure |
|---|---|---|---|
| GitHub App private key (`aap-reader`) | 90 days, or immediately on suspicion | Key Vault (key or secret), GitHub App settings | 1. Generate a new private key in the App settings (GitHub allows multiple active keys). 2. Import to Key Vault as a new version. 3. Restart workers / wait for the config refresh. Verify token minting. 4. Delete the old key in GitHub. 5. Disable the old Key Vault version. |
| GitHub webhook secret | 180 days | Key Vault, App settings | 1. Receiver accepts the **current and next** secret (dual-secret mode). 2. Set the next secret in Key Vault, then in GitHub. 3. After 24h of deliveries verifying with the new secret, remove the old one. |
| Jira service token | 90 days | Key Vault | Create a new token for the service account → Key Vault new version → verify a sync → revoke the old token |
| DefectDojo API key (platform user) | 90 days | Key Vault | Regenerate in DefectDojo (this invalidates the old key immediately) → update Key Vault right away → expect a short connector error window. Schedule off-peak. |
| Dependency-Track API key (platform team) | 90 days | Key Vault | Add a new key to the team → Key Vault → verify → delete the old key |
| Session encryption key | 365 days | Key Vault | Add the new key as primary. Keep the old as decrypt-only for 8h (max session). Then remove. |
| Database access | n/a | Entra auth (managed identity) | No passwords to rotate. Ensure password auth stays disabled for application roles. |
| Cloud access (Azure/AWS) | n/a | Managed identity / web identity federation | No secrets. Review role assignments quarterly. |
| **Legacy: repo-held DD/DT keys** (the earlier prototype's pattern) | Retire | Consumer repo secrets | After migration (E07-F03-S02): delete the repo secrets **and** revoke the keys in DD/DT. Rotating alone is not enough, because every repo writer had access. |

**Expiry alerts:** every Key Vault secret has `expires` set. An Azure Monitor alert fires 14 days before.

**Emergency rotation:** follow the same steps without overlap where compromise is suspected (revoke first, accept the outage), and open a P1/P2 incident.
