# SPDX-License-Identifier: Apache-2.0
# Everything Azure + Entra for one environment, from nothing (ADR-031). Apply order is handled by Terraform; the
# human steps that remain are in docs/operations/integration-bootstrap.md.

module "platform" {
  source                     = "../../modules/platform"
  name                       = var.name
  location                   = var.location
  tags                       = var.tags
  image                      = var.image
  public_hostname            = var.public_hostname
  postgres_high_availability = var.production
  evidence_worm_state        = var.evidence_worm_state
  operator_ip_ranges         = var.operator_ip_ranges
  secret_officer_object_ids  = var.secret_officer_object_ids
  app_settings = merge(
    module.entra.app_settings,
    module.sentinel.app_settings,
    module.scanners.app_settings,
    {
      AAP_AZURE_SUBSCRIPTIONS = join(",", module.azure_reader.subscriptions)
      AAP_GITHUB_ORG          = var.github_org
    },
    var.github_app_client_id == "" ? {} : { AAP_GITHUB_APP_CLIENT_ID = var.github_app_client_id },
    var.github_app_key_id == "" ? {} : { AAP_GITHUB_APP_KEY_ID = var.github_app_key_id },
    var.jira_url == "" ? {} : { AAP_JIRA_URL = var.jira_url, AAP_JIRA_EMAIL = var.jira_email },
    var.aws_role_arn == "" ? {} : { AAP_AWS_ROLE_ARN = var.aws_role_arn, AAP_AWS_ACCOUNTS = join(",", var.aws_accounts) },
  )
}

module "entra" {
  source                    = "../../modules/entra"
  display_prefix            = var.production ? "FortProof" : "FortProof (${var.name})"
  public_url                = module.platform.public_url
  api_identifier            = "${var.name}-api"
  api_identity_principal_id = module.platform.identities.api.principal_id
  owner_object_ids          = var.secret_officer_object_ids
  scoped_groups             = var.scoped_groups
}

module "sentinel" {
  source                 = "../../modules/sentinel"
  name                   = var.name
  location               = var.location
  resource_group_name    = module.platform.resource_group_name
  workspace_id           = module.platform.log_analytics_workspace_id
  publisher_principal_id = module.platform.identities.worker.principal_id
  tags                   = var.tags
}

module "scanners" {
  source                       = "../../modules/scanners"
  name                         = var.name
  location                     = var.location
  resource_group_name          = module.platform.resource_group_name
  container_app_environment_id = module.platform.container_app_environment_id
  key_vault_id                 = module.platform.key_vault_id
  key_vault_uri                = module.platform.key_vault_uri
  registry_id                  = module.platform.registry_id
  registry_login_server        = module.platform.registry_login_server
  platform_image               = var.image
  postgres_fqdn                = module.platform.postgres_fqdn
  postgres_admin_password      = module.platform.postgres_admin_password
  ui_allowed_cidrs             = var.scanner_ui_allowed_cidrs
  mail_domain                  = var.mail_domain
  tags                         = var.tags
}

module "azure_reader" {
  source       = "../../modules/azure-reader"
  principal_id = module.platform.identities.worker.principal_id
  scopes       = var.defender_scopes
}
