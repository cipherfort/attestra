# SPDX-License-Identifier: Apache-2.0
variable "name" {
  description = "Short name used in resource names, e.g. aap-prod"
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,15}$", var.name))
    error_message = "3-16 chars, lowercase letters, digits and hyphens."
  }
}

variable "location" {
  description = "Azure region, e.g. westeurope, eastus2, uksouth"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "address_space" {
  description = "VNet range: /23 for Container Apps, /27 private endpoints, /28 PostgreSQL"
  type        = string
  default     = "10.40.0.0/22"
}

variable "image" {
  description = "Platform image (built and pushed by CI), e.g. <acr>.azurecr.io/aap:<git sha>. Empty = placeholder until the first release."
  type        = string
  default     = ""
}

variable "public_hostname" {
  description = "Custom HTTPS hostname for the API/UI (optional). Empty = the Container Apps default FQDN."
  type        = string
  default     = ""
}

variable "postgres_sku" {
  type    = string
  default = "GP_Standard_D2ds_v5"
}

variable "postgres_high_availability" {
  description = "Zone-redundant standby (prod)"
  type        = bool
  default     = false
}

variable "evidence_retention_days" {
  description = "WORM retention for evidence blobs (ADR-017 retention policy: 7 years)"
  type        = number
  default     = 2555
}

variable "evidence_worm_state" {
  description = "Unlocked during the pilot (can still be shortened). Locking is irreversible: REQUIRES HUMAN APPROVAL (decision log D-0xx)."
  type        = string
  default     = "Unlocked"
  validation {
    condition     = contains(["Unlocked", "Locked", "Disabled"], var.evidence_worm_state)
    error_message = "Unlocked, Locked or Disabled."
  }
}

variable "operator_ip_ranges" {
  description = "CIDRs allowed to reach Key Vault from outside the VNet (operators running `aap bootstrap` from a workstation). Empty = private only."
  type        = list(string)
  default     = []
}

variable "secret_officer_object_ids" {
  description = "Entra object ids allowed to write integration secrets (Key Vault Secrets Officer): the people who run `aap bootstrap`."
  type        = list(string)
  default     = []
}

variable "app_settings" {
  description = "Non-secret integration settings from other modules / tfvars (AAP_OIDC_*, AAP_SENTINEL_*, AAP_DT_URL, ...)."
  type        = map(string)
  default     = {}
}

variable "github_deploy_subjects" {
  description = "GitHub OIDC subjects allowed to deploy, e.g. [\"repo:acme/devsec-dashboard:environment:production\"]. Empty = no CI deploy identity."
  type        = list(string)
  default     = []
}
