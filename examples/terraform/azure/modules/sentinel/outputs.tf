# SPDX-License-Identifier: Apache-2.0
output "app_settings" {
  value = {
    AAP_SENTINEL_DCE          = azurerm_monitor_data_collection_endpoint.this.logs_ingestion_endpoint
    AAP_SENTINEL_DCR_ID       = azurerm_monitor_data_collection_rule.this.immutable_id
    AAP_SENTINEL_WORKSPACE_ID = var.workspace_id
  }
}
