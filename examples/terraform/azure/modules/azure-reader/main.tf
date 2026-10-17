# SPDX-License-Identifier: Apache-2.0
# Read-only access for Defender for Cloud posture (ADR-019): Reader + Security Reader for the worker identity at the
# scopes the organisation decides to cover (management groups or subscriptions). Applied by someone with
# User Access Administrator (or Owner) at those scopes; the scopes list is a governance decision (decision log).

variable "principal_id" {
  description = "Worker managed identity principal id"
  type        = string
}

variable "scopes" {
  description = "Resource ids: /providers/Microsoft.Management/managementGroups/<id> or /subscriptions/<id>"
  type        = list(string)
}

resource "azurerm_role_assignment" "reader" {
  for_each             = toset(var.scopes)
  scope                = each.value
  role_definition_name = "Reader"
  principal_id         = var.principal_id
}

resource "azurerm_role_assignment" "security_reader" {
  for_each             = toset(var.scopes)
  scope                = each.value
  role_definition_name = "Security Reader"
  principal_id         = var.principal_id
}

output "subscriptions" {
  description = "Subscription ids among the scopes (for AAP_AZURE_SUBSCRIPTIONS; management groups need their subscriptions listed)"
  value       = [for s in var.scopes : split("/", s)[2] if startswith(s, "/subscriptions/")]
}
