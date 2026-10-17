# SPDX-License-Identifier: Apache-2.0
# Platform foundation (ADR-025): network, identities, Key Vault, PostgreSQL, WORM evidence storage, registry,
# Container Apps environment and the platform's own apps. Everything private except the API/UI and webhook ingress.

data "azurerm_client_config" "current" {}

locals {
  n       = var.name
  compact = replace(var.name, "-", "")
  image   = var.image != "" ? var.image : "mcr.microsoft.com/k8se/quickstart:latest" # placeholder until the first release
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.n}"
  location = var.location
  tags     = var.tags
}

# ------------------------------------------------------------------------------------------ identities
# One identity per process, so each gets only what it needs (access control model ACM-07).

resource "azurerm_user_assigned_identity" "api" {
  name                = "id-${local.n}-api"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "worker" {
  name                = "id-${local.n}-worker"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "hook" {
  name                = "id-${local.n}-hook"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

# ------------------------------------------------------------------------------------------ network

resource "azurerm_virtual_network" "this" {
  name                = "vnet-${local.n}"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "apps" {
  name                 = "snet-apps"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.address_space, 1, 0)] # /23
  delegation {
    name = "aca"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "endpoints" {
  name                 = "snet-endpoints"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.address_space, 5, 16)] # /27
}

resource "azurerm_subnet" "postgres" {
  name                 = "snet-postgres"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.address_space, 6, 34)] # /28
  delegation {
    name = "pg"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Default-deny inbound from the internet on every subnet; Container Apps ingress is handled by the platform-managed
# load balancer, PostgreSQL and private endpoints only accept traffic from inside the VNet.
resource "azurerm_network_security_group" "subnets" {
  for_each            = toset(["apps", "endpoints", "postgres"])
  name                = "nsg-${local.n}-${each.key}"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  dynamic "security_rule" {
    for_each = each.key == "apps" ? [] : [1]
    content {
      name                       = "deny-internet-inbound"
      priority                   = 4000
      direction                  = "Inbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "Internet"
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "subnets" {
  for_each = {
    apps      = azurerm_subnet.apps.id
    endpoints = azurerm_subnet.endpoints.id
    postgres  = azurerm_subnet.postgres.id
  }
  subnet_id                 = each.value
  network_security_group_id = azurerm_network_security_group.subnets[each.key].id
}

resource "azurerm_private_dns_zone" "zones" {
  for_each            = toset(["privatelink.blob.core.windows.net", "privatelink.vaultcore.azure.net", "${local.n}.private.postgres.database.azure.com"])
  name                = each.value
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "zones" {
  for_each              = azurerm_private_dns_zone.zones
  name                  = "link-${local.n}"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = each.value.name
  virtual_network_id    = azurerm_virtual_network.this.id
}

# ------------------------------------------------------------------------------------------ observability

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.n}"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

# ------------------------------------------------------------------------------------------ Key Vault

resource "azurerm_key_vault" "this" {
  name                          = "kv-${local.compact}-${substr(sha1(azurerm_resource_group.this.id), 0, 4)}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.this.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium" # HSM-backed keys for the GitHub App signing key
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = length(var.operator_ip_ranges) > 0
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.operator_ip_ranges
  }
  tags = var.tags
}

resource "azurerm_private_endpoint" "kv" {
  name                = "pe-${local.n}-kv"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = azurerm_subnet.endpoints.id
  private_service_connection {
    name                           = "kv"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "kv"
    private_dns_zone_ids = [azurerm_private_dns_zone.zones["privatelink.vaultcore.azure.net"].id]
  }
}

resource "azurerm_role_assignment" "kv_secrets_reader" {
  for_each             = { api = azurerm_user_assigned_identity.api.principal_id, worker = azurerm_user_assigned_identity.worker.principal_id, hook = azurerm_user_assigned_identity.hook.principal_id }
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value
}

resource "azurerm_role_assignment" "kv_crypto_worker" { # signs GitHub App JWTs with the non-exportable key
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.worker.principal_id
}

resource "azurerm_role_assignment" "kv_officers" {
  for_each             = toset(concat(var.secret_officer_object_ids, [data.azurerm_client_config.current.object_id]))
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = each.value
}

resource "azurerm_role_assignment" "kv_crypto_officers" { # import the GitHub App key once (bootstrap)
  for_each             = toset(var.secret_officer_object_ids)
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = each.value
}

# ------------------------------------------------------------------------------------------ PostgreSQL

resource "random_password" "pg_admin" {
  length  = 40
  special = false
}

resource "azurerm_postgresql_flexible_server" "this" {
  #checkov:skip=CKV2_AZURE_57:VNet-injected (delegated subnet, private DNS), public access disabled: private by construction
  name                          = "psql-${local.n}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.this.name
  version                       = "16"
  sku_name                      = var.postgres_sku
  storage_mb                    = 65536
  backup_retention_days         = 35
  geo_redundant_backup_enabled  = true
  delegated_subnet_id           = azurerm_subnet.postgres.id
  private_dns_zone_id           = azurerm_private_dns_zone.zones["${local.n}.private.postgres.database.azure.com"].id
  public_network_access_enabled = false
  administrator_login           = "aapadmin"
  administrator_password        = random_password.pg_admin.result
  zone                          = "1"
  authentication {
    password_auth_enabled         = true
    active_directory_auth_enabled = true
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }
  dynamic "high_availability" {
    for_each = var.postgres_high_availability ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }
  tags       = var.tags
  depends_on = [azurerm_private_dns_zone_virtual_network_link.zones]
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_configuration" "require_tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_database" "dbs" {
  for_each  = toset(["aap", "dependencytrack", "defectdojo"])
  name      = each.value
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_key_vault_secret" "database_url" {
  name         = "database-url"
  key_vault_id = azurerm_key_vault.this.id
  #checkov:skip=CKV_AZURE_41:Rotation is runbook-driven (docs/runbooks/key-rotation.md); an expiry would take the platform down
  value        = "postgresql+psycopg://aapadmin:${random_password.pg_admin.result}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/aap?sslmode=require"
  content_type = "text/plain"
  depends_on   = [azurerm_role_assignment.kv_officers]
}

# ------------------------------------------------------------------------------------------ evidence storage (WORM)

resource "azurerm_storage_account" "evidence" {
  #checkov:skip=CKV2_AZURE_1:Microsoft-managed keys + infrastructure (double) encryption; CMK is PROPOSED (decision log)
  #checkov:skip=CKV_AZURE_33:No queues are used; blob read/write/delete logs go to Log Analytics (diagnostic setting below)
  name                              = "st${local.compact}ev${substr(sha1(azurerm_resource_group.this.id), 0, 4)}"
  location                          = var.location
  resource_group_name               = azurerm_resource_group.this.name
  account_tier                      = "Standard"
  account_replication_type          = "GZRS"
  account_kind                      = "StorageV2"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  shared_access_key_enabled         = false # Entra (managed identity) only
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true
  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
  immutability_policy { # version-level WORM for every blob in the account
    allow_protected_append_writes = false
    state                         = var.evidence_worm_state
    period_since_creation_in_days = var.evidence_retention_days
  }
  tags = var.tags
  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container" "evidence" {
  #checkov:skip=CKV2_AZURE_21:Blob read logging is a diagnostic setting on the blob service (evidence_reads below)
  name                  = "evidence"
  storage_account_id    = azurerm_storage_account.evidence.id # management plane: works with public access disabled
  container_access_type = "private"
}

# Every read, write and delete attempt on evidence is logged (who read which evidence; a WORM violation attempt).
resource "azurerm_monitor_diagnostic_setting" "evidence_reads" {
  name                       = "evidence-access"
  target_resource_id         = "${azurerm_storage_account.evidence.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}

resource "azurerm_private_endpoint" "blob" {
  name                = "pe-${local.n}-blob"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = azurerm_subnet.endpoints.id
  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.evidence.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.zones["privatelink.blob.core.windows.net"].id]
  }
}

resource "azurerm_role_assignment" "evidence_writer" { # only ingestion writes evidence (ACM-07)
  scope                = azurerm_storage_container.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.worker.principal_id
}

resource "azurerm_role_assignment" "evidence_reader" {
  scope                = azurerm_storage_container.evidence.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}

# ------------------------------------------------------------------------------------------ registry

resource "azurerm_container_registry" "this" {
  #checkov:skip=CKV_AZURE_139:Standard SKU (no private link); RBAC pull only, admin and anonymous pull disabled. Premium + PE is PROPOSED
  #checkov:skip=CKV_AZURE_233:Premium-only (zone redundancy); PROPOSED with the Premium decision
  #checkov:skip=CKV_AZURE_165:Single-region deployment (DR plan rebuilds from the release pipeline)
  #checkov:skip=CKV_AZURE_166:Images are scanned in CI and carry SLSA provenance attestations (ADR-030) verified before deploy
  #checkov:skip=CKV_AZURE_164:Content trust is deprecated; provenance attestations replace it (ADR-030)
  #checkov:skip=CKV_AZURE_167:Premium-only (retention policy); untagged manifests are purged by the release pipeline
  #checkov:skip=CKV_AZURE_237:Premium-only (dedicated data endpoints)
  name                   = "cr${local.compact}${substr(sha1(azurerm_resource_group.this.id), 0, 4)}"
  location               = var.location
  resource_group_name    = azurerm_resource_group.this.name
  sku                    = "Standard"
  admin_enabled          = false
  anonymous_pull_enabled = false
  tags                   = var.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  for_each             = { api = azurerm_user_assigned_identity.api.principal_id, worker = azurerm_user_assigned_identity.worker.principal_id, hook = azurerm_user_assigned_identity.hook.principal_id }
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = each.value
}
