# SPDX-License-Identifier: Apache-2.0
variable "display_prefix" {
  type    = string
  default = "FortProof"
}

variable "public_url" {
  description = "https URL of the platform UI/API (redirect URI = <public_url>/auth/callback)"
  type        = string
  validation {
    condition     = startswith(var.public_url, "https://")
    error_message = "Must be https."
  }
}

variable "api_identifier" {
  description = "Suffix of the API's identifier URI: api://<api_identifier>"
  type        = string
}

variable "api_identity_principal_id" {
  description = "Object (principal) id of the API container app's user-assigned managed identity"
  type        = string
}

variable "owner_object_ids" {
  description = "Additional owners of the app registrations and groups (the platform team leads)"
  type        = list(string)
  default     = []
}

variable "scoped_groups" {
  description = "Scoped role groups to create, e.g. [\"champion-claims\", \"unit-lead-benefits\"]"
  type        = list(string)
  default     = []
}
