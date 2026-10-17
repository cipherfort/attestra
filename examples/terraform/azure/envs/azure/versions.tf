# SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.81" }
    azuread = { source = "hashicorp/azuread", version = "~> 3.10" }
    azapi   = { source = "azure/azapi", version = "~> 2.13" }
    random  = { source = "hashicorp/random", version = "~> 3.9" }
  }
  # terraform init -backend-config=../../state-bootstrap/<env>.backend.hcl -backend-config="key=azure-<env>.tfstate"
  backend "azurerm" {}
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
  subscription_id     = var.subscription_id
  storage_use_azuread = true
}

provider "azuread" {}
provider "azapi" {}
