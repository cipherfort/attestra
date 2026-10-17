# SPDX-License-Identifier: Apache-2.0
output "app_settings" {
  description = "Environment for the platform apps"
  value = {
    AAP_OIDC_ISSUER       = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/v2.0"
    AAP_OIDC_CLIENT_ID    = azuread_application.web.client_id
    AAP_OIDC_TENANT_ID    = data.azuread_client_config.current.tenant_id
    AAP_OIDC_API_AUDIENCE = azuread_application.api.client_id # v2 access tokens carry the client id as `aud`
    AAP_OIDC_CLIENT_AUTH  = "managed_identity"
  }
}

output "role_groups" {
  description = "Group object ids by platform role (add people to these to grant org-wide roles)"
  value       = { for k, g in azuread_group.roles : k => g.object_id }
}

output "scoped_groups" {
  description = "Scoped group object ids: map them to platform role assignments (principal_type entra_group)"
  value       = { for k, g in azuread_group.scoped : k => g.object_id }
}
