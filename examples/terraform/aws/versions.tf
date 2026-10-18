# SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.69" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = { app = "fortproof", managed-by = "terraform" } }
}
