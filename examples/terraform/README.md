# Reference Terraform (examples)

Examples to copy and adapt, not the supported install path (that is the [Helm chart](../../charts/attestra/README.md)).
Both are validated against the real provider schemas and scanned by Checkov in CI. Neither has been applied by this
project to a real account: expect first-apply adjustments.

| Example | Creates |
|---|---|
| [`aws/`](aws/README.md) | EKS (private endpoint, IMDSv2 hop limit 1), RDS PostgreSQL 16 (encrypted, TLS-only, managed master password, Multi-AZ, 35-day backups), an S3 evidence bucket with **Object Lock in COMPLIANCE mode**, KMS, access logs, and an IRSA role that can add and read evidence but never delete it |
| [`azure/`](azure/README.md) | The original reference deployment: Container Apps, PostgreSQL Flexible Server, Blob with version-level WORM, Key Vault, Entra ID app registrations and roles, Sentinel, the scanners, the AWS Security Hub reader role and the GitHub organization settings |
