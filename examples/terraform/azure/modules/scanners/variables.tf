# SPDX-License-Identifier: Apache-2.0
variable "name" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "container_app_environment_id" { type = string }
variable "key_vault_id" { type = string }
variable "postgres_fqdn" { type = string }
variable "postgres_admin_password" {
  type      = string
  sensitive = true
}
variable "mail_domain" {
  type    = string
  default = "example.org"
}
variable "ui_allowed_cidrs" {
  description = "If set, the DT and DD UIs get external ingress restricted to these CIDRs. Empty = VNet only."
  type        = list(string)
  default     = []
}
variable "tags" {
  type    = map(string)
  default = {}
}
variable "key_vault_uri" { type = string }
variable "registry_id" { type = string }
variable "registry_login_server" { type = string }
variable "platform_image" {
  description = "Platform image used by the bootstrap jobs (empty until the first release)"
  type        = string
  default     = ""
}
