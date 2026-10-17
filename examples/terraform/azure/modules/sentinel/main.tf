# SPDX-License-Identifier: Apache-2.0
# Microsoft Sentinel for the platform's curated events (ADR-020), created from nothing on the platform's workspace.
# The table/stream schema comes from columns.auto.json, generated from aap.connectors.sentinel.STREAM_COLUMNS and
# checked by tests/integration/test_connector_sync.py::test_terraform_dcr_stream_matches_code.

locals {
  columns = jsondecode(file("${path.module}/columns.auto.json"))
  table   = "AppSecPlatform_CL"
  stream  = "Custom-AppSecPlatform"
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id                 = var.workspace_id
  customer_managed_key_enabled = false
}

resource "azapi_resource" "table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = local.table
  parent_id = var.workspace_id
  body = {
    properties = {
      plan                 = "Analytics"
      retentionInDays      = var.retention_days
      totalRetentionInDays = var.total_retention_days # checkpoints are the external tamper anchor (ADR-016/017)
      schema = {
        name    = local.table
        columns = local.columns
      }
    }
  }
}

resource "azurerm_monitor_data_collection_endpoint" "this" {
  name                          = "dce-${var.name}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  public_network_access_enabled = true # Logs Ingestion over TLS with Entra auth; AMPLS is a later hardening step
  tags                          = var.tags
}

resource "azurerm_monitor_data_collection_rule" "this" {
  name                        = "dcr-${var.name}-appsec"
  resource_group_name         = var.resource_group_name
  location                    = var.location
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.this.id

  destinations {
    log_analytics {
      workspace_resource_id = var.workspace_id
      name                  = "workspace"
    }
  }

  data_flow {
    streams       = [local.stream]
    destinations  = ["workspace"]
    output_stream = "Custom-${local.table}"
    transform_kql = "source"
  }

  stream_declaration {
    stream_name = local.stream
    dynamic "column" {
      for_each = local.columns
      content {
        name = column.value.name
        type = column.value.type
      }
    }
  }
  tags       = var.tags
  depends_on = [azapi_resource.table]
}

# The worker may publish to this one rule and nothing else.
resource "azurerm_role_assignment" "publisher" {
  scope                = azurerm_monitor_data_collection_rule.this.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = var.publisher_principal_id
}

# log-source health (siem.log_source_health): read-only queries on the workspace
resource "azurerm_role_assignment" "reader" {
  scope                = var.workspace_id
  role_definition_name = "Log Analytics Reader"
  principal_id         = var.publisher_principal_id
}
