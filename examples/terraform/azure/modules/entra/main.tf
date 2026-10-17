# SPDX-License-Identifier: Apache-2.0
# Entra ID for the platform (ADR-014, access control model §2), created from nothing.
#
# * aap-web: the BFF's confidential client. Authenticates with a FEDERATED CREDENTIAL of the API's managed identity
#   (no client secret exists). App roles = the platform's org-wide roles; tokens carry `roles` and the object ids of
#   the app-assigned groups only (`ApplicationGroup`, so no group overage).
# * aap-api: resource for service clients (client credentials) with app role Reports.Read.
# * Groups aap-role-<role>, assigned to the matching app role. Membership is managed by people (or access packages),
#   never by the platform. Scoped roles (champion, directorate lead) are platform role assignments keyed by group.
#
# Who can apply: an Entra role holder with Application Administrator + Groups Administrator (or Privileged Role
# Administrator for the app role assignments). That person is part of THIS project (RACI), not another team.

data "azuread_client_config" "current" {}

locals {
  org_wide_roles = {
    appsec_engineer     = "AppSec engineer: organisation-wide read, triage, false-positive confirmation"
    governance_analyst  = "Governance analyst: organisation-wide read and reporting"
    security_leadership = "Security leadership: organisation-wide read, exception decisions"
    executive           = "Executive: aggregates only"
    auditor             = "Auditor: organisation-wide read-only (time-bound)"
    platform_admin      = "Platform administrator: operations only, no finding detail (PIM eligible only)"
    engineer            = "Engineer: team scope via platform team membership"
  }
  scoped_groups = toset(var.scoped_groups) # e.g. champion-claims, directorate-lead-benefits
}

resource "random_uuid" "role" {
  for_each = local.org_wide_roles
}

resource "random_uuid" "reports_read" {}

resource "azuread_application" "web" {
  display_name            = "${var.display_prefix} (web)"
  sign_in_audience        = "AzureADMyOrg"
  group_membership_claims = ["ApplicationGroup"]
  owners                  = concat([data.azuread_client_config.current.object_id], var.owner_object_ids)

  web {
    redirect_uris = ["${var.public_url}/auth/callback"]
    logout_url    = "${var.public_url}/"
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  api {
    requested_access_token_version = 2
  }

  dynamic "app_role" {
    for_each = local.org_wide_roles
    content {
      id                   = random_uuid.role[app_role.key].result
      value                = app_role.key
      display_name         = app_role.key
      description          = app_role.value
      allowed_member_types = ["User"]
      enabled              = true
    }
  }

  optional_claims {
    id_token {
      name = "email"
    }
    id_token {
      name = "groups"
    }
  }

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    resource_access {
      id   = "37f7f235-527c-4136-accd-4a02d197296e" # openid
      type = "Scope"
    }
    resource_access {
      id   = "14dad69e-099b-42c9-810b-d002981feec1" # profile
      type = "Scope"
    }
    resource_access {
      id   = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0" # email
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "web" {
  client_id                    = azuread_application.web.client_id
  app_role_assignment_required = true # only members of an assigned group can sign in at all
  owners                       = [data.azuread_client_config.current.object_id]
}

# The API's managed identity is the web app's credential: no secret to store, rotate or leak.
resource "azuread_application_federated_identity_credential" "web_mi" {
  #checkov:skip=CKV_AZURE_249:Not a GitHub Actions trust: the subject is one managed identity's immutable object id
  application_id = azuread_application.web.id
  display_name   = "container-app-managed-identity"
  description    = "aap-api user-assigned managed identity (token exchange)"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/v2.0"
  subject        = var.api_identity_principal_id
}

resource "azuread_application" "api" {
  display_name     = "${var.display_prefix} (api)"
  sign_in_audience = "AzureADMyOrg"
  identifier_uris  = ["api://${var.api_identifier}"]
  owners           = concat([data.azuread_client_config.current.object_id], var.owner_object_ids)
  api {
    requested_access_token_version = 2
  }
  app_role {
    id                   = random_uuid.reports_read.result
    value                = "Reports.Read"
    display_name         = "Reports.Read"
    description          = "Service clients (e.g. BI): aggregate reports only"
    allowed_member_types = ["Application"]
    enabled              = true
  }
}

resource "azuread_service_principal" "api" {
  client_id                    = azuread_application.api.client_id
  app_role_assignment_required = true
  owners                       = [data.azuread_client_config.current.object_id]
}

resource "azuread_group" "roles" {
  for_each         = local.org_wide_roles
  display_name     = "aap-role-${replace(each.key, "_", "-")}"
  description      = each.value
  security_enabled = true
  owners           = concat([data.azuread_client_config.current.object_id], var.owner_object_ids)
}

resource "azuread_app_role_assignment" "roles" {
  for_each            = local.org_wide_roles
  app_role_id         = random_uuid.role[each.key].result
  principal_object_id = azuread_group.roles[each.key].object_id
  resource_object_id  = azuread_service_principal.web.object_id
}

# Scoped groups carry no app role. They are assigned to the app (so they appear in the token's `groups` claim)
# with the default access role, and the platform maps them to scoped role assignments (role_assignments table).
resource "azuread_group" "scoped" {
  for_each         = local.scoped_groups
  display_name     = "aap-${each.value}"
  security_enabled = true
  owners           = concat([data.azuread_client_config.current.object_id], var.owner_object_ids)
}

resource "azuread_app_role_assignment" "scoped" {
  for_each            = local.scoped_groups
  app_role_id         = "00000000-0000-0000-0000-000000000000" # default access
  principal_object_id = azuread_group.scoped[each.key].object_id
  resource_object_id  = azuread_service_principal.web.object_id
}
