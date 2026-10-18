# AWS example: EKS + RDS + S3 Object Lock

Status: IMPLEMENTED as an example; `terraform validate` and Checkov (81 passed, 0 failed, 6 justified skips) pass in
CI. Not applied by this project.

```bash
terraform init
terraform apply -var region=eu-west-1 -var 'availability_zones=["eu-west-1a","eu-west-1b","eu-west-1c"]' \
  -var 'cluster_admin_arns=["arn:aws:iam::123456789012:role/platform-admins"]'
terraform output -json helm_values > aap-values.json   # merge into your Helm values
```

Then:
1. Create the database logins' URLs: the migration job creates the `aap_*_login` roles; give each a random password
   in the `aap-secrets` Secret (`database-url-api`, ...) and the admin URL (`database-url`) from the RDS master
   secret (`terraform output database`). See [the chart README](../../../charts/fortproof/README.md).
2. Install the chart with the values from `helm_values`: the service-account annotation gives the platform its
   S3 role through IRSA, so no storage keys exist anywhere.

Decisions to make before applying:
- **Retention** (`evidence_retention_days`, default 7 years). COMPLIANCE mode cannot be shortened or removed once
  objects are written, not even by the account root user.
- **Cross-region replication** of the evidence bucket (skipped here: a cost and data-residency decision).
- **Cluster access**: the API endpoint is private; reach it through your VPN or a bastion.
