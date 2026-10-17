# SPDX-License-Identifier: Apache-2.0
output "app_settings" {
  value = {
    AAP_DT_URL = "https://${azurerm_container_app.dtrack.ingress[0].fqdn}"
    AAP_DD_URL = "https://${azurerm_container_app.dd["ddnginx"].ingress[0].fqdn}"
  }
}
output "bootstrap_jobs" { value = { for k, j in azurerm_container_app_job.bootstrap : k => j.name } }
