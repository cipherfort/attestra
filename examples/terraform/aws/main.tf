# SPDX-License-Identifier: Apache-2.0
# EXAMPLE: FortProof on AWS. EKS for the Helm chart, RDS PostgreSQL 16, an S3 evidence bucket with
# Object Lock (COMPLIANCE) and KMS, and an IRSA role so the platform reaches S3 without keys. See README.md.

locals {
  azs = var.availability_zones
}

module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=b3abd6df2ecf052451a361ed55b8f06f8742a795" # v6.7.3

  name                 = var.name
  cidr                 = var.vpc_cidr
  azs                  = local.azs
  private_subnets      = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets       = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, 200 + i)]
  database_subnets     = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, 210 + i)]
  enable_nat_gateway   = true
  single_nat_gateway   = false
  enable_dns_hostnames = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true

  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1 }
  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
}

module "eks" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-eks.git?ref=91f11ea01656c26b8e6b8eb1b74f19863f60056c" # v21.29.0

  name                   = var.name
  kubernetes_version     = var.kubernetes_version
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_subnets
  endpoint_public_access = false # reach the API from inside the VPC (VPN, bastion) only

  enable_irsa                              = true
  enable_cluster_creator_admin_permissions = false
  access_entries = { for i, arn in var.cluster_admin_arns : "admin-${i}" => {
    principal_arn = arn
    policy_associations = { admin = {
      policy_arn   = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
      access_scope = { type = "cluster" }
    } }
  } }

  encryption_config = { resources = ["secrets"] }

  eks_managed_node_groups = {
    default = {
      instance_types = ["m7g.large"]
      ami_type       = "AL2023_ARM_64_STANDARD"
      min_size       = 2
      max_size       = 4
      desired_size   = 2
      metadata_options = {
        http_tokens                 = "required"
        http_put_response_hop_limit = 1 # pods cannot reach the instance metadata service
      }
    }
  }
}
