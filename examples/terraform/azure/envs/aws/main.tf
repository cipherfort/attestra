# SPDX-License-Identifier: Apache-2.0
# AWS side of cloud posture (ADR-019), applied by an administrator of the Security Hub aggregation account.
terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.68" }
  }
  backend "s3" {} # or any backend the project chooses; state contains no secrets
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-west-2"
}
variable "tenant_id" { type = string }
variable "worker_principal_id" {
  description = "envs/azure output worker_identity.principal_id"
  type        = string
}

module "reader" {
  source                        = "../../modules/aws-reader"
  tenant_id                     = var.tenant_id
  managed_identity_principal_id = var.worker_principal_id
}

output "app_settings" { value = module.reader.app_settings }
