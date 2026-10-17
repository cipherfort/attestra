# SPDX-License-Identifier: Apache-2.0
# Run ONCE with local state, before anything else: creates the storage that holds every other root's Terraform
# state. Entra-only access (no shared keys), versioning and soft delete, a delete lock. Keep this root's local
# state file somewhere safe (it only describes these few resources).
#
#   terraform init && terraform apply -var location=<azure-region> -var name=aap
#
terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.81" }
  }
}

provider "azurerm" {
  features {}
  storage_use_azuread = true
}

variable "name" { type = string }
variable "location" { type = string }

resource "azurerm_resource_group" "state" {
  name     = "rg-${var.name}-tfstate"
  location = var.location
}

resource "azurerm_storage_account" "state" {
  #checkov:skip=CKV2_AZURE_33:Operators and CI run Terraform from outside any VNet; access is Entra-only (no shared keys)
  #checkov:skip=CKV_AZURE_59:Same: network-reachable but no anonymous or key-based access is possible
  #checkov:skip=CKV2_AZURE_1:State holds no evidence; Microsoft-managed keys
  #checkov:skip=CKV_AZURE_33:No queues are used
  name                            = "st${replace(var.name, "-", "")}tf${substr(sha1(azurerm_resource_group.state.id), 0, 6)}"
  resource_group_name             = azurerm_resource_group.state.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "GZRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "state" {
  #checkov:skip=CKV2_AZURE_21:State access is audited through Entra sign-in logs and the activity log
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

resource "azurerm_management_lock" "state" {
  name       = "do-not-delete"
  scope      = azurerm_storage_account.state.id
  lock_level = "CanNotDelete"
  notes      = "Terraform state for Attestra"
}

output "backend_config" {
  value = <<-EOT
    resource_group_name  = "${azurerm_resource_group.state.name}"
    storage_account_name = "${azurerm_storage_account.state.name}"
    container_name       = "tfstate"
    use_azuread_auth     = true
  EOT
}
