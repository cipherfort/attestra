# SPDX-License-Identifier: Apache-2.0
variable "subscription_id" { type = string }
variable "name" {
  description = "e.g. aap-dev, aap-prod"
  type        = string
}
variable "location" {
  description = "Azure region, e.g. westeurope, eastus2, uksouth"
  type        = string
}
variable "production" {
  type    = bool
  default = false
}
variable "tags" {
  type    = map(string)
  default = { service = "attestra" }
}
variable "image" {
  description = "<registry>/aap:<git sha>, set by the release pipeline. Empty on the very first apply."
  type        = string
  default     = ""
}
variable "public_hostname" {
  type    = string
  default = ""
}
variable "mail_domain" {
  type    = string
  default = "example.org"
}
variable "evidence_worm_state" {
  type    = string
  default = "Unlocked"
}
variable "operator_ip_ranges" {
  type    = list(string)
  default = []
}
variable "secret_officer_object_ids" {
  description = "People who run `aap bootstrap` (write secrets) and co-own the Entra apps"
  type        = list(string)
  default     = []
}
variable "scoped_groups" {
  type    = list(string)
  default = []
}
variable "defender_scopes" {
  description = "Management groups / subscriptions whose Defender for Cloud posture the platform reads"
  type        = list(string)
  default     = []
}
variable "scanner_ui_allowed_cidrs" {
  type    = list(string)
  default = []
}
# Filled in after the human bootstrap steps (docs/operations/integration-bootstrap.md); empty = not configured yet.
variable "github_org" {
  type    = string
  default = ""
}
variable "github_app_client_id" {
  type    = string
  default = ""
}
variable "github_app_key_id" {
  description = "Key Vault key id of the imported GitHub App private key (non-exportable)"
  type        = string
  default     = ""
}
variable "jira_url" {
  type    = string
  default = ""
}
variable "jira_email" {
  type    = string
  default = ""
}
variable "aws_role_arn" {
  description = "Output of envs/aws"
  type        = string
  default     = ""
}
variable "aws_accounts" {
  type    = list(string)
  default = []
}
variable "github_deploy_subjects" {
  description = "e.g. [\"repo:acme/attestra:environment:production\"]"
  type        = list(string)
  default     = []
}
