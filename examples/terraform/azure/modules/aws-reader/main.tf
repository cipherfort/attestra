# SPDX-License-Identifier: Apache-2.0
# AWS Security Hub read access for the platform, with no AWS keys (ADR-019).
#
# The platform's worker managed identity gets an Entra token (audience below) and exchanges it at AWS STS
# (AssumeRoleWithWebIdentity). This module creates, in the Security Hub delegated-administrator / aggregation account:
#   * an IAM OIDC identity provider trusting the Entra tenant's v2 issuer;
#   * a role assumable ONLY by that one managed identity (sub = its principal id) for that audience;
#   * read-only Security Hub permissions.
# Apply with an AWS administrator of that account. Use Security Hub cross-region aggregation and organization
# delegated administration so one role in one account sees every member account's findings.
#
# Verify on first deploy (`aap integrations status`, then a connector run): the claims Entra issues for managed
# identity tokens (iss/aud/sub) must match the trust policy; `aap` logs the token's claims if STS refuses it.

variable "tenant_id" { type = string }

variable "managed_identity_principal_id" {
  description = "Object (principal) id of the worker's user-assigned managed identity"
  type        = string
}

variable "audience" {
  description = "Token audience requested by the worker (AAP_AWS_WEB_IDENTITY_AUDIENCE)"
  type        = string
  default     = "api://AzureADTokenExchange"
}

variable "role_name" {
  type    = string
  default = "aap-securityhub-reader"
}

locals {
  issuer_host = "login.microsoftonline.com/${var.tenant_id}/v2.0"
}

resource "aws_iam_openid_connect_provider" "entra" {
  url            = "https://${local.issuer_host}"
  client_id_list = [var.audience]
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.entra.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.issuer_host}:aud"
      values   = [var.audience]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.issuer_host}:sub"
      values   = [var.managed_identity_principal_id]
    }
  }
}

resource "aws_iam_role" "reader" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  description          = "FortProof: read Security Hub findings (Entra workload identity, no keys)"
}

resource "aws_iam_role_policy_attachment" "securityhub_read" {
  role       = aws_iam_role.reader.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess"
}

output "app_settings" {
  value = {
    AAP_AWS_ROLE_ARN              = aws_iam_role.reader.arn
    AAP_AWS_WEB_IDENTITY_AUDIENCE = var.audience
  }
}
