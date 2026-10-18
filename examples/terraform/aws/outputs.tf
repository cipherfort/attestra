# SPDX-License-Identifier: Apache-2.0
output "helm_values" {
  description = "Values for charts/fortproof (merge with your settings)"
  value = {
    serviceAccount = { annotations = { "eks.amazonaws.com/role-arn" = aws_iam_role.platform.arn } }
    settings = {
      evidence_store = { kind = "s3", bucket = aws_s3_bucket.evidence.bucket, region = var.region }
    }
    networkPolicy = { postgres = { cidr = var.vpc_cidr, port = 5432 } }
  }
}

output "database" {
  description = "Create the database-url* keys of the aap-secrets Secret from these (admin password: Secrets Manager)"
  value = {
    endpoint         = aws_db_instance.aap.address
    admin_user       = aws_db_instance.aap.username
    admin_secret_arn = aws_db_instance.aap.master_user_secret[0].secret_arn
  }
}

output "cluster_name" { value = module.eks.cluster_name }
