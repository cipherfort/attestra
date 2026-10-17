# SPDX-License-Identifier: Apache-2.0
# Analytics rules for the curated events (config/siem-events.yaml soc_action). Incidents go to the SOC queue the
# project sets up in Sentinel; the SOC lead approves the event list (REQUIRES HUMAN APPROVAL, E18-F01-S01).

locals {
  rules = {
    secret-active = {
      name     = "AppSec: active secret exposed in a repository"
      severity = "High"
      query    = "AppSecPlatform_CL | where EventType == 'secret.exposed_active'"
      tactics  = ["CredentialAccess"]
    }
    malicious-package = {
      name     = "AppSec: malicious package in a build or dependency"
      severity = "High"
      query    = "AppSecPlatform_CL | where EventType == 'package.malicious_detected'"
      tactics  = ["InitialAccess"]
    }
    kev-internet = {
      name     = "AppSec: known-exploited vulnerability on an internet-facing application"
      severity = "High"
      query    = "AppSecPlatform_CL | where EventType == 'vuln.kev_internet_exposed'"
      tactics  = ["InitialAccess"]
    }
    integrity = {
      name     = "AppSec platform: evidence integrity failure"
      severity = "High"
      query    = "AppSecPlatform_CL | where EventType == 'evidence.integrity_failure'"
      tactics  = ["DefenseEvasion"]
    }
    untrusted-producer = {
      name     = "AppSec platform: repeated forged or unapproved evidence"
      severity = "Medium"
      query    = "AppSecPlatform_CL | where EventType == 'evidence.untrusted_producer'"
      tactics  = ["DefenseEvasion"]
    }
    sod = {
      name     = "AppSec platform: segregation-of-duties violation attempt"
      severity = "Medium"
      query    = "AppSecPlatform_CL | where EventType == 'authz.sod_violation_attempt'"
      tactics  = ["PrivilegeEscalation"]
    }
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "events" {
  for_each                   = local.rules
  name                       = "aap-${each.key}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  display_name               = each.value.name
  severity                   = each.value.severity
  query                      = each.value.query
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = each.value.tactics
  event_grouping {
    aggregation_method = "AlertPerResult"
  }
  entity_mapping {
    entity_type = "CloudApplication"
    field_mapping {
      identifier  = "Name"
      column_name = "AppKey"
    }
  }
  depends_on = [azapi_resource.table]
}

# The daily checkpoint is the external tamper-evidence anchor: its absence is itself an incident.
resource "azurerm_sentinel_alert_rule_scheduled" "checkpoint_missing" {
  name                       = "aap-checkpoint-missing"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  display_name               = "AppSec platform: no evidence checkpoint received in 26 hours"
  severity                   = "Medium"
  query                      = "AppSecPlatform_CL | where TimeGenerated > ago(26h) | where EventType == 'checkpoint.daily' | count | where Count == 0"
  query_frequency            = "PT1H"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion"]
  depends_on                 = [azapi_resource.table]
}
