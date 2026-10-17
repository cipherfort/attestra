# SPDX-License-Identifier: Apache-2.0
# Container Apps: api (UI + API, public HTTPS), hook (GitHub webhooks, public HTTPS), worker (no ingress) and jobs
# that must run inside the VNet (migrations, bootstrap of internal services).

resource "azurerm_container_app_environment" "this" {
  name                               = "cae-${local.n}"
  location                           = var.location
  resource_group_name                = azurerm_resource_group.this.name
  log_analytics_workspace_id         = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id           = azurerm_subnet.apps.id
  infrastructure_resource_group_name = "rg-${local.n}-aca-infra"
  internal_load_balancer_enabled     = false
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
  tags = var.tags
}

locals {
  public_url = var.public_hostname != "" ? "https://${var.public_hostname}" : "https://ca-${local.n}-api.${azurerm_container_app_environment.this.default_domain}"
  common_env = merge({
    AAP_ENV              = "production"
    AAP_AUTH_MODE        = "oidc"
    AAP_PUBLIC_URL       = local.public_url
    AAP_SECRETS_BACKEND  = "keyvault"
    AAP_KEYVAULT_URL     = azurerm_key_vault.this.vault_uri
    AAP_BLOB_ACCOUNT_URL = azurerm_storage_account.evidence.primary_blob_endpoint
    AAP_BLOB_CONTAINER   = azurerm_storage_container.evidence.name
  }, var.app_settings)
  apps = {
    api    = { identity = azurerm_user_assigned_identity.api, command = ["aap", "api", "--host", "0.0.0.0", "--port", "8000"], port = 8000, external = true, min = 1 }
    hook   = { identity = azurerm_user_assigned_identity.hook, command = ["aap", "hook", "--host", "0.0.0.0", "--port", "8001"], port = 8001, external = true, min = 1 }
    worker = { identity = azurerm_user_assigned_identity.worker, command = ["aap", "worker"], port = null, external = false, min = 1 }
  }
}

resource "azurerm_container_app" "apps" {
  for_each                     = local.apps
  name                         = "ca-${local.n}-${each.key}"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"

  identity {
    type         = "UserAssigned"
    identity_ids = [each.value.identity.id]
  }

  registry {
    server   = azurerm_container_registry.this.login_server
    identity = each.value.identity.id
  }

  secret {
    # per-process login (risk R-25): written by the migrate job (`aap db provision-logins`), never the admin URL
    name                = "database-url"
    key_vault_secret_id = "${azurerm_key_vault.this.vault_uri}secrets/database-url-${each.key}"
    identity            = each.value.identity.id
  }

  dynamic "ingress" {
    for_each = each.value.port == null ? [] : [1]
    content {
      external_enabled = each.value.external
      target_port      = each.value.port
      transport        = "http"
      traffic_weight {
        latest_revision = true
        percentage      = 100
      }
    }
  }

  template {
    min_replicas = each.value.min
    max_replicas = each.key == "worker" ? 3 : 5
    container {
      name    = each.key
      image   = local.image
      cpu     = each.key == "worker" ? 1.0 : 0.5
      memory  = each.key == "worker" ? "2Gi" : "1Gi"
      command = var.image != "" ? each.value.command : null
      env {
        name        = "AAP_DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name  = "AAP_AZURE_CLIENT_ID"
        value = each.value.identity.client_id
      }
      dynamic "env" {
        for_each = local.common_env
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "liveness_probe" {
        for_each = each.key == "api" ? [1] : []
        content {
          transport = "HTTP"
          port      = 8000
          path      = "/api/v1/health/live"
        }
      }
    }
  }
  tags       = var.tags
  depends_on = [azurerm_role_assignment.kv_secrets_reader, azurerm_role_assignment.acr_pull]
}

# Jobs run inside the VNet: they reach PostgreSQL, Key Vault and the internal scanners. The migrate job has its own
# identity: the only one that holds the administrator URL and may write the per-process database URLs.
resource "azurerm_user_assigned_identity" "migrator" {
  name                = "id-${local.n}-migrator"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_role_assignment" "migrator_kv" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.migrator.principal_id
}

resource "azurerm_role_assignment" "migrator_pull" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.migrator.principal_id
}
locals {
  jobs = {
    migrate = ["sh", "-c", "aap migrate && aap config load --git-sha \"$AAP_GIT_SHA\" && aap db provision-logins all"]
  }
}

resource "azurerm_container_app_job" "jobs" {
  for_each                     = local.jobs
  name                         = "job-${local.n}-${each.key}"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 0
  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.migrator.id]
  }
  registry {
    server   = azurerm_container_registry.this.login_server
    identity = azurerm_user_assigned_identity.migrator.id
  }
  secret {
    name                = "database-url"
    key_vault_secret_id = azurerm_key_vault_secret.database_url.versionless_id # the administrator: migrations only
    identity            = azurerm_user_assigned_identity.migrator.id
  }
  template {
    container {
      name    = each.key
      image   = local.image
      cpu     = 0.5
      memory  = "1Gi"
      command = var.image != "" ? each.value : null
      env {
        name        = "AAP_DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name  = "AAP_AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.migrator.client_id
      }
      dynamic "env" {
        for_each = local.common_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
  tags = var.tags
}

# ------------------------------------------------------------------------------------------ CI/CD deploy identity
# The release workflow logs in with GitHub OIDC (no stored Azure secret), pushes the image, runs the migration job
# and updates the platform's own container apps. It cannot read Key Vault secrets or evidence.

resource "azurerm_user_assigned_identity" "deploy" {
  count               = length(var.github_deploy_subjects) > 0 ? 1 : 0
  name                = "id-${local.n}-deploy"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "deploy" {
  for_each            = toset(var.github_deploy_subjects)
  name                = substr(replace(each.value, "/[^A-Za-z0-9-]/", "-"), 0, 120)
  resource_group_name = azurerm_resource_group.this.name
  parent_id           = azurerm_user_assigned_identity.deploy[0].id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = each.value
}

resource "azurerm_role_assignment" "deploy_push" {
  count                = length(var.github_deploy_subjects) > 0 ? 1 : 0
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.deploy[0].principal_id
}

resource "azurerm_role_assignment" "deploy_apps" {
  for_each = length(var.github_deploy_subjects) > 0 ? merge(
    { for k, a in azurerm_container_app.apps : "app-${k}" => a.id },
    { for k, j in azurerm_container_app_job.jobs : "job-${k}" => j.id },
  ) : {}
  scope                = each.value
  role_definition_name = "Contributor" # scoped to one app/job each: image updates and job starts only
  principal_id         = azurerm_user_assigned_identity.deploy[0].principal_id
}
