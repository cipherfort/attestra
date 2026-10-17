# SPDX-License-Identifier: Apache-2.0
output "public_url" { value = module.platform.public_url }
output "webhook_url" { value = module.platform.webhook_url }
output "registry" { value = module.platform.registry_login_server }
output "key_vault_uri" { value = module.platform.key_vault_uri }
output "role_groups" { value = module.entra.role_groups }
output "scoped_groups" { value = module.entra.scoped_groups }
output "worker_identity" {
  description = "Feed principal_id and the tenant to envs/aws"
  value       = module.platform.identities.worker
}
output "tenant_id" { value = module.entra.app_settings.AAP_OIDC_TENANT_ID }
output "deploy" {
  description = "Variables for the GitHub environment used by examples/github-actions/deploy-azure-container-apps.yml"
  value = {
    AZURE_CLIENT_ID       = module.platform.deploy_client_id
    AZURE_TENANT_ID       = module.entra.app_settings.AAP_OIDC_TENANT_ID
    AZURE_SUBSCRIPTION_ID = var.subscription_id
    ACR                   = module.platform.registry_login_server
    RESOURCE_GROUP        = module.platform.resource_group_name
    APPS                  = join(",", values(module.platform.app_names))
    MIGRATE_JOB           = module.platform.migrate_job_name
  }
}
output "bootstrap_jobs" { value = module.scanners.bootstrap_jobs }
