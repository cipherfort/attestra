# SPDX-License-Identifier: Apache-2.0
variable "name" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "workspace_id" {
  description = "Log Analytics workspace resource id to onboard to Sentinel"
  type        = string
}
variable "publisher_principal_id" {
  description = "Worker managed identity: publishes events, reads log-source health"
  type        = string
}
variable "retention_days" {
  type    = number
  default = 90
}
variable "total_retention_days" {
  description = "Interactive + archive. ≥ evidence retention (7 years) for checkpoints (ADR-017)."
  type        = number
  default     = 2556
}
variable "tags" {
  type    = map(string)
  default = {}
}
