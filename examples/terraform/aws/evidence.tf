# SPDX-License-Identifier: Apache-2.0
# Evidence: write once. Object Lock in COMPLIANCE mode means no one (including the account root) can delete or
# overwrite a stored version before retention ends. The platform also refuses to overwrite (conditional writes) and
# re-hashes on read.
resource "aws_s3_bucket" "evidence" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is a disaster-recovery choice for each adopter (cost, data residency); add it per policy
  #checkov:skip=CKV2_AWS_62:Event notifications are not used; the platform reads evidence it wrote itself
  bucket_prefix       = "${var.name}-evidence-"
  object_lock_enabled = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
  # No expiry: Object Lock decides when evidence may go, and the platform's retention policy decides whether to.
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence/"
}

# Server access logs for the evidence bucket (who read or tried to change evidence).
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the access-log bucket; logging it to itself would loop
  #checkov:skip=CKV_AWS_144:See the evidence bucket
  #checkov:skip=CKV2_AWS_62:Not used
  #checkov:skip=CKV_AWS_145:S3 server access logging supports only SSE-S3 on the target bucket
  bucket_prefix = "${var.name}-access-logs-"
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "keep-one-year"
    status = "Enabled"
    filter {}
    expiration { days = 400 }
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.aap.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TLSOnly"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

locals {
  # the chart's naming: the release name if it already contains "attestra", else <release>-attestra
  service_account = strcontains(var.release, "attestra") ? var.release : "${var.release}-attestra"
}

# The platform's service account (IRSA): read and add evidence, nothing else. No delete, no lock changes.
resource "aws_iam_role" "platform" {
  name = "${var.name}-platform"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.eks.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${module.eks.oidc_provider}:sub" = "system:serviceaccount:${var.namespace}:${local.service_account}"
        "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "platform_evidence" {
  name = "evidence-write-once"
  role = aws_iam_role.platform.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
      Resource = "${aws_s3_bucket.evidence.arn}/*" },
      { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"],
      Resource = aws_s3_bucket.evidence.arn },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = aws_kms_key.aap.arn },
    ]
  })
}
