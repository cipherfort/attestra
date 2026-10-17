# SPDX-License-Identifier: Apache-2.0
output "resource_group_name" { value = azurerm_resource_group.this.name }
output "location" { value = var.location }
output "public_url" { value = local.public_url }
output "webhook_url" { value = "https://${azurerm_container_app.apps["hook"].ingress[0].fqdn}/github/webhook" }
output "key_vault_id" { value = azurerm_key_vault.this.id }
output "key_vault_uri" { value = azurerm_key_vault.this.vault_uri }
output "log_analytics_workspace_id" { value = azurerm_log_analytics_workspace.this.id }
output "log_analytics_workspace_guid" { value = azurerm_log_analytics_workspace.this.workspace_id }
output "container_app_environment_id" { value = azurerm_container_app_environment.this.id }
output "container_app_environment_domain" { value = azurerm_container_app_environment.this.default_domain }
output "registry_login_server" { value = azurerm_container_registry.this.login_server }
output "postgres_fqdn" { value = azurerm_postgresql_flexible_server.this.fqdn }
output "postgres_admin_password" {
  value     = random_password.pg_admin.result
  sensitive = true
}
output "identities" {
  value = {
    api    = { id = azurerm_user_assigned_identity.api.id, principal_id = azurerm_user_assigned_identity.api.principal_id, client_id = azurerm_user_assigned_identity.api.client_id }
    worker = { id = azurerm_user_assigned_identity.worker.id, principal_id = azurerm_user_assigned_identity.worker.principal_id, client_id = azurerm_user_assigned_identity.worker.client_id }
    hook   = { id = azurerm_user_assigned_identity.hook.id, principal_id = azurerm_user_assigned_identity.hook.principal_id, client_id = azurerm_user_assigned_identity.hook.client_id }
  }
}
output "evidence_container_id" { value = azurerm_storage_container.evidence.id }
output "deploy_client_id" {
  description = "AZURE_CLIENT_ID for the release workflow (GitHub environment variable, not a secret)"
  value       = length(var.github_deploy_subjects) > 0 ? azurerm_user_assigned_identity.deploy[0].client_id : null
}
output "app_names" { value = { for k, a in azurerm_container_app.apps : k => a.name } }
output "migrate_job_name" { value = azurerm_container_app_job.jobs["migrate"].name }
output "registry_id" { value = azurerm_container_registry.this.id }
