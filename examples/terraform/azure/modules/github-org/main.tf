# SPDX-License-Identifier: Apache-2.0
# GitHub organization baseline for the platform (ADR-005/006, GitHub security baseline standard), from nothing.
# Applied by a GitHub organization OWNER (token with admin:org, repo) — a person on this project, not another team.
#
# Creates: the `security-workflows` repository that hosts the approved reusable workflows (trusted producers), its
# protection ruleset, the `appsec-platform` team that owns it, and organization Actions policy.
# Does NOT create the GitHub App: GitHub requires an owner's click for that (aap bootstrap github-app).
# Organization-wide rulesets and code security configurations depend on the plan (Team / Enterprise); they are
# variables, off by default, so this applies cleanly on any plan.

variable "org" { type = string }

variable "appsec_maintainers" {
  description = "GitHub logins of the platform team (maintainers of appsec-platform)"
  type        = list(string)
}

variable "workflow_repo_visibility" {
  description = "private works on every plan; internal (Enterprise) lets all org repos call the workflows without extra access settings"
  type        = string
  default     = "private"
}

variable "org_rulesets_available" {
  description = "true when the plan supports organization rulesets (GitHub Team or Enterprise)"
  type        = bool
  default     = false
}

resource "github_team" "appsec" {
  name        = "appsec-platform"
  description = "Owns FortProof, its reusable workflows and trusted-producer approvals"
  privacy     = "closed"
}

resource "github_team_membership" "appsec" {
  for_each = toset(var.appsec_maintainers)
  team_id  = github_team.appsec.id
  username = each.value
  role     = "maintainer"
}

resource "github_repository" "security_workflows" {
  #checkov:skip=CKV_GIT_3:Enabled by github_repository_vulnerability_alerts (the provider deprecated the inline argument)
  name                        = "security-workflows"
  description                 = "Approved reusable security workflows (called by application repos, pinned by SHA)"
  visibility                  = var.workflow_repo_visibility
  has_issues                  = true
  has_wiki                    = false
  has_projects                = false
  delete_branch_on_merge      = true
  allow_merge_commit          = false
  allow_rebase_merge          = false
  web_commit_signoff_required = true
  auto_init                   = true
  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "github_repository_vulnerability_alerts" "security_workflows" {
  repository = github_repository.security_workflows.name
  enabled    = true
}

resource "github_team_repository" "security_workflows" {
  team_id    = github_team.appsec.id
  repository = github_repository.security_workflows.name
  permission = "maintain"
}

resource "github_repository_file" "codeowners" {
  repository          = github_repository.security_workflows.name
  file                = ".github/CODEOWNERS"
  content             = "* @${var.org}/appsec-platform\n"
  commit_message      = "Require appsec-platform review for every change"
  overwrite_on_create = true
}

resource "github_repository_ruleset" "security_workflows_main" {
  name        = "protect-default-branch"
  repository  = github_repository.security_workflows.name
  target      = "branch"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }
  rules {
    deletion                = true
    non_fast_forward        = true
    required_linear_history = true
    required_signatures     = true
    pull_request {
      required_approving_review_count   = 2
      require_code_owner_review         = true
      dismiss_stale_reviews_on_push     = true
      require_last_push_approval        = true
      required_review_thread_resolution = true
    }
  }
}

resource "github_repository_ruleset" "release_tags" { # releases (approved SHAs) cannot be moved or deleted
  name        = "immutable-release-tags"
  repository  = github_repository.security_workflows.name
  target      = "tag"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["refs/tags/v*"]
      exclude = []
    }
  }
  rules {
    deletion         = true
    non_fast_forward = true
    update           = true
  }
}

resource "github_actions_organization_permissions" "this" {
  allowed_actions      = "selected"
  enabled_repositories = "all"
  allowed_actions_config {
    github_owned_allowed = true
    verified_allowed     = false
    patterns_allowed     = ["${var.org}/security-workflows/*"]
  }
}

resource "github_organization_ruleset" "workflow_files" {
  count       = var.org_rulesets_available ? 1 : 0
  name        = "aap-protect-security-config"
  target      = "branch"
  enforcement = "evaluate" # observe first (control framework: observe mode), then active
  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
    repository_name {
      include = ["~ALL"]
      exclude = []
    }
  }
  rules {
    deletion         = true
    non_fast_forward = true
    pull_request {
      required_approving_review_count = 1
      require_code_owner_review       = true
    }
  }
}

output "workflow_repository" {
  value = "${var.org}/${github_repository.security_workflows.name}"
}

# Private application repositories may call the private reusable workflows (Settings → Actions → Access).
resource "github_actions_repository_access_level" "security_workflows" {
  repository   = github_repository.security_workflows.name
  access_level = "organization"
}
