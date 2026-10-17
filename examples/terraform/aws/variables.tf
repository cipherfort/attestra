# SPDX-License-Identifier: Apache-2.0
variable "region" {
  type        = string
  description = "AWS region (no default: choose where your data may live)"
}
variable "availability_zones" {
  type        = list(string)
  description = "Three availability zones, named explicitly so the network never changes shape when AWS adds a zone"
  validation {
    condition     = length(var.availability_zones) == 3
    error_message = "Give exactly three availability zones."
  }
}
variable "name" {
  type    = string
  default = "attestra"
}
variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}
variable "kubernetes_version" {
  type    = string
  default = "1.33"
}
variable "namespace" {
  type        = string
  default     = "attestra"
  description = "Kubernetes namespace of the Helm release"
}
variable "release" {
  type        = string
  default     = "attestra"
  description = "Helm release name (the chart names its service account <release>, or <release>-attestra)"
}
variable "evidence_retention_days" {
  type        = number
  default     = 2555
  description = "Object Lock COMPLIANCE retention for evidence (7 years by default). Cannot be shortened once applied."
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}
variable "multi_az" {
  type    = bool
  default = true
}
variable "cluster_admin_arns" {
  type        = list(string)
  default     = []
  description = "IAM principals granted cluster admin through EKS access entries"
}
