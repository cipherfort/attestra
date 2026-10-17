# SPDX-License-Identifier: Apache-2.0
# GitHub organization baseline, applied by an organization owner (GITHUB_TOKEN with admin:org + repo, or `gh auth`).
terraform {
  required_version = ">= 1.9"
  required_providers {
    github = { source = "integrations/github", version = "~> 6.13" }
  }
  backend "azurerm" {}
}

provider "github" {
  owner = var.org
}

variable "org" { type = string }
variable "appsec_maintainers" { type = list(string) }
variable "org_rulesets_available" {
  type    = bool
  default = false
}

module "org" {
  source                 = "../../modules/github-org"
  org                    = var.org
  appsec_maintainers     = var.appsec_maintainers
  org_rulesets_available = var.org_rulesets_available
}

output "workflow_repository" {
  description = "Set as workflow_repository in config/trusted-producers.yaml (PR)"
  value       = module.org.workflow_repository
}
