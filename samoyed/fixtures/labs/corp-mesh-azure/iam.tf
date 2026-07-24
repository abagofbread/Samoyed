# Illustrative only — fake principal / subscription IDs, not for apply.

resource "azurerm_user_assigned_identity" "bastion" {
  name                = "mi-bastion"
  resource_group_name = "rg-dmz"
  location            = "eastus"
}

resource "azurerm_user_assigned_identity" "app" {
  name                = "mi-app-api"
  resource_group_name = "rg-app"
  location            = "eastus"
}

resource "azurerm_user_assigned_identity" "automation" {
  name                = "mi-automation"
  resource_group_name = "rg-app"
  location            = "eastus"
}

resource "azurerm_role_assignment" "bastion_controls_webapp" {
  scope                = azurerm_linux_web_app.api.id
  role_definition_name = "Website Contributor"
  principal_id         = azurerm_user_assigned_identity.bastion.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "app_reads_kv" {
  scope                = azurerm_key_vault.pci.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "automation_owner" {
  scope                = "/subscriptions/22222222-2222-2222-2222-222222222222"
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.automation.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_federated_identity_credential" "github" {
  name     = "github-oidc"
  parent_id = azurerm_user_assigned_identity.app.id
  issuer   = "https://token.actions.githubusercontent.com"
  subject  = "repo:corp/app:ref:refs/heads/main"
  audience = ["api://AzureADTokenExchange"]
}
