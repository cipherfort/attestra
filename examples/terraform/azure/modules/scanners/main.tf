# SPDX-License-Identifier: Apache-2.0
# Dependency-Track 4.14.5 and DefectDojo 3.4.0 on the platform's Container Apps environment, using databases on the
# platform's PostgreSQL server (ADR-009, ADR-018, ADR-031). Same versions as deploy/local/compose.yaml, which is where
# their bootstrap and the platform's connectors are tested against the real services.
#
# Ingress is INTERNAL by default (reachable from the platform and from the VNet only). AppSec engineers reach the
# UIs through the VNet (VPN/Bastion) or, if `ui_allowed_cidrs` is set, through external ingress restricted to those
# ranges. Credentials are generated here into Key Vault; `aap bootstrap dependency-track|defectdojo` (run as the
# Container Apps jobs below, inside the VNet) creates the platform's least-privilege service accounts.

locals {
  n           = var.name
  pg_user     = "aapadmin"
  dt_jdbc     = "jdbc:postgresql://${var.postgres_fqdn}:5432/dependencytrack?sslmode=require"
  dd_database = "postgresql://${local.pg_user}:${var.postgres_admin_password}@${var.postgres_fqdn}:5432/defectdojo?sslmode=require"
  ui_external = length(var.ui_allowed_cidrs) > 0
}

resource "random_password" "dd" {
  for_each = toset(["secret-key", "aes-key", "admin-password"])
  length   = each.key == "aes-key" ? 32 : 48
  special  = false
}

resource "azurerm_key_vault_secret" "dd" {
  #checkov:skip=CKV_AZURE_41:Rotation is runbook-driven (docs/runbooks/key-rotation.md); an expiry would stop DefectDojo
  for_each     = random_password.dd
  name         = "defectdojo-${each.key}"
  key_vault_id = var.key_vault_id
  value        = each.value.result
  content_type = "text/plain"
}

resource "azurerm_key_vault_secret" "dd_database_url" {
  #checkov:skip=CKV_AZURE_41:Rotation is runbook-driven (docs/runbooks/key-rotation.md)
  name         = "defectdojo-database-url"
  key_vault_id = var.key_vault_id
  value        = local.dd_database
  content_type = "text/plain"
}

resource "azurerm_key_vault_secret" "pg_password" {
  #checkov:skip=CKV_AZURE_41:Rotation is runbook-driven (docs/runbooks/key-rotation.md)
  name         = "postgres-admin-password"
  key_vault_id = var.key_vault_id
  value        = var.postgres_admin_password
  content_type = "text/plain"
}

resource "azurerm_user_assigned_identity" "scanners" {
  name                = "id-${local.n}-scanners"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_role_assignment" "kv" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.scanners.principal_id
}

# ------------------------------------------------------------------------------------------ Dependency-Track

resource "azurerm_container_app" "dtrack" {
  name                         = "ca-${local.n}-dtrack"
  container_app_environment_id = var.container_app_environment_id
  resource_group_name          = var.resource_group_name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.scanners.id]
  }
  secret {
    name                = "pg-password"
    key_vault_secret_id = azurerm_key_vault_secret.pg_password.versionless_id
    identity            = azurerm_user_assigned_identity.scanners.id
  }
  ingress {
    external_enabled = local.ui_external
    target_port      = 8080
    transport        = "http"
    dynamic "ip_security_restriction" {
      for_each = var.ui_allowed_cidrs
      content {
        name             = "allow-${ip_security_restriction.key}"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
      }
    }
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
  template {
    min_replicas = 1
    max_replicas = 1 # DT's API server is not horizontally scalable (in-process index)
    container {
      name   = "apiserver"
      image  = "docker.io/dependencytrack/apiserver:4.14.5"
      cpu    = 2.0
      memory = "4Gi"
      env {
        name  = "ALPINE_DATABASE_MODE"
        value = "external"
      }
      env {
        name  = "ALPINE_DATABASE_URL"
        value = local.dt_jdbc
      }
      env {
        name  = "ALPINE_DATABASE_DRIVER"
        value = "org.postgresql.Driver"
      }
      env {
        name  = "ALPINE_DATABASE_USERNAME"
        value = local.pg_user
      }
      env {
        name        = "ALPINE_DATABASE_PASSWORD"
        secret_name = "pg-password"
      }
      env {
        name  = "EXTRA_JAVA_OPTIONS"
        value = "-Xmx3g"
      }
      liveness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/api/version"
        initial_delay           = 60
        failure_count_threshold = 5
      }
      # /data (search indexes, mirror cache) is ephemeral: rebuilt on restart. State lives in PostgreSQL.
    }
  }
  tags = var.tags
}

# ------------------------------------------------------------------------------------------ DefectDojo

locals {
  dd_secret_env = {
    DD_DATABASE_URL           = "defectdojo-database-url"
    DD_SECRET_KEY             = "defectdojo-secret-key"
    DD_CREDENTIAL_AES_256_KEY = "defectdojo-aes-key"
    DD_ADMIN_PASSWORD         = "defectdojo-admin-password"
  }
  dd_env = {
    DD_CELERY_BROKER_URL = "redis://ca-${local.n}-ddvalkey:6379/0"
    DD_ALLOWED_HOSTS     = "*"
    DD_ADMIN_USER        = "admin"
    DD_ADMIN_MAIL        = "appsec-platform@${var.mail_domain}"
    DD_INITIALIZE        = "false"
    DD_JIRA_ENABLED      = "False" # ADR-018: the platform is the only ticket writer
  }
  dd_secret_ids = merge(
    { for k, s in azurerm_key_vault_secret.dd : "defectdojo-${k}" => s.versionless_id },
    { "defectdojo-database-url" = azurerm_key_vault_secret.dd_database_url.versionless_id },
  )
  dd_apps = {
    ddvalkey = { image = "docker.io/valkey/valkey:8-alpine", command = null, port = 6379, transport = "tcp", external = false, cpu = 0.5, memory = "1Gi", dd = false }
    dduwsgi  = { image = "docker.io/defectdojo/defectdojo-django:3.4.0", command = ["/entrypoint-uwsgi.sh"], port = 3031, transport = "tcp", external = false, cpu = 1.0, memory = "2Gi", dd = true }
    ddworker = { image = "docker.io/defectdojo/defectdojo-django:3.4.0", command = ["/entrypoint-celery-worker.sh"], port = null, transport = null, external = false, cpu = 1.0, memory = "2Gi", dd = true }
    ddnginx  = { image = "docker.io/defectdojo/defectdojo-nginx:3.4.0", command = null, port = 8080, transport = "http", external = local.ui_external, cpu = 0.5, memory = "1Gi", dd = false }
  }
}

resource "azurerm_container_app" "dd" {
  for_each                     = local.dd_apps
  name                         = "ca-${local.n}-${each.key}"
  container_app_environment_id = var.container_app_environment_id
  resource_group_name          = var.resource_group_name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.scanners.id]
  }
  dynamic "secret" {
    for_each = each.value.dd ? local.dd_secret_ids : {}
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.scanners.id
    }
  }
  dynamic "ingress" {
    for_each = each.value.port == null ? [] : [1]
    content {
      external_enabled = each.value.external
      target_port      = each.value.port
      exposed_port     = each.value.transport == "tcp" ? each.value.port : null
      transport        = each.value.transport
      dynamic "ip_security_restriction" {
        for_each = each.value.external ? var.ui_allowed_cidrs : []
        content {
          name             = "allow-${ip_security_restriction.key}"
          action           = "Allow"
          ip_address_range = ip_security_restriction.value
        }
      }
      traffic_weight {
        latest_revision = true
        percentage      = 100
      }
    }
  }
  template {
    min_replicas = 1
    max_replicas = 1
    container {
      name    = each.key
      image   = each.value.image
      cpu     = each.value.cpu
      memory  = each.value.memory
      command = each.value.command
      dynamic "env" {
        for_each = each.value.dd ? local.dd_secret_env : {}
        content {
          name        = env.key
          secret_name = env.value
        }
      }
      dynamic "env" {
        for_each = each.value.dd ? local.dd_env : (each.key == "ddnginx" ? { DD_UWSGI_HOST = "ca-${local.n}-dduwsgi", DD_UWSGI_PORT = "3031", NGINX_METRICS_ENABLED = "false" } : {})
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
  tags       = var.tags
  depends_on = [azurerm_role_assignment.kv]
}

# Database migrations + initial admin (DD's initializer), run once after deploy and on each DD upgrade.
resource "azurerm_container_app_job" "dd_initializer" {
  name                         = "job-${local.n}-dd-init"
  location                     = var.location
  resource_group_name          = var.resource_group_name
  container_app_environment_id = var.container_app_environment_id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 1
  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.scanners.id]
  }
  dynamic "secret" {
    for_each = local.dd_secret_ids
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.scanners.id
    }
  }
  template {
    container {
      name    = "initializer"
      image   = "docker.io/defectdojo/defectdojo-django:3.4.0"
      cpu     = 1.0
      memory  = "2Gi"
      command = ["/entrypoint-initializer.sh"]
      dynamic "env" {
        for_each = local.dd_secret_env
        content {
          name        = env.key
          secret_name = env.value
        }
      }
      dynamic "env" {
        for_each = merge(local.dd_env, { DD_INITIALIZE = "true" })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
  tags       = var.tags
  depends_on = [azurerm_role_assignment.kv]
}

# ------------------------------------------------------------------------------------------ bootstrap jobs
# `aap bootstrap dependency-track|defectdojo` must reach the internal services, so they run as jobs in the VNet.
# A dedicated identity may WRITE integration secrets (Secrets Officer); the running platform can only read them.

resource "azurerm_user_assigned_identity" "bootstrap" {
  name                = "id-${local.n}-bootstrap"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_role_assignment" "bootstrap_kv" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.bootstrap.principal_id
}

resource "azurerm_role_assignment" "bootstrap_pull" {
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.bootstrap.principal_id
}

locals {
  bootstrap_jobs = {
    dtrack = ["aap", "bootstrap", "dependency-track", "--url", "https://${azurerm_container_app.dtrack.ingress[0].fqdn}"]
    dd     = ["aap", "bootstrap", "defectdojo", "--url", "https://${azurerm_container_app.dd["ddnginx"].ingress[0].fqdn}", "--admin-password-env", "DD_ADMIN_PASSWORD"]
  }
}

resource "azurerm_container_app_job" "bootstrap" {
  for_each                     = var.platform_image == "" ? {} : local.bootstrap_jobs
  name                         = "job-${local.n}-boot-${each.key}"
  location                     = var.location
  resource_group_name          = var.resource_group_name
  container_app_environment_id = var.container_app_environment_id
  replica_timeout_in_seconds   = 900
  replica_retry_limit          = 0
  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.bootstrap.id]
  }
  registry {
    server   = var.registry_login_server
    identity = azurerm_user_assigned_identity.bootstrap.id
  }
  secret {
    name                = "defectdojo-admin-password"
    key_vault_secret_id = azurerm_key_vault_secret.dd["admin-password"].versionless_id
    identity            = azurerm_user_assigned_identity.bootstrap.id
  }
  template {
    container {
      name    = "bootstrap"
      image   = var.platform_image
      cpu     = 0.5
      memory  = "1Gi"
      command = each.value
      env {
        name  = "AAP_SECRETS_BACKEND"
        value = "keyvault"
      }
      env {
        name  = "AAP_KEYVAULT_URL"
        value = var.key_vault_uri
      }
      env {
        name  = "AAP_AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.bootstrap.client_id
      }
      env {
        name  = "AAP_ENV"
        value = "production"
      }
      env {
        name        = "DD_ADMIN_PASSWORD"
        secret_name = "defectdojo-admin-password"
      }
    }
  }
  tags       = var.tags
  depends_on = [azurerm_role_assignment.bootstrap_kv, azurerm_role_assignment.bootstrap_pull]
}
