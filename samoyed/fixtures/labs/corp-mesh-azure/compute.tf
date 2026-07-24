# Illustrative only — fake subscription IDs, not for apply.

resource "azurerm_linux_virtual_machine" "bastion" {
  name                = "vm-bastion-01"
  resource_group_name = "rg-dmz"
  location            = "eastus"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "azureuser"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.bastion.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}

resource "azurerm_linux_web_app" "api" {
  name                = "app-corp-api"
  resource_group_name = "rg-app"
  location            = "eastus"
  service_plan_id     = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-app/providers/Microsoft.Web/serverFarms/plan-app"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  site_config {}
}

resource "azurerm_key_vault" "pci" {
  name                = "corp-kv-pci"
  location            = "eastus"
  resource_group_name = "rg-app"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}

resource "azurerm_key_vault_secret" "crown_jewel" {
  name         = "customer-pii-export"
  key_vault_id = azurerm_key_vault.pci.id
  value        = "redacted"
}

resource "azurerm_storage_account" "artifacts" {
  name                     = "corpartifactsapp"
  resource_group_name      = "rg-app"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_container_registry" "shared" {
  name                = "corpacrshared"
  resource_group_name = "rg-app"
  location            = "eastus"
  sku                 = "Basic"
}

resource "azurerm_automation_account" "ops" {
  name                = "aa-corp-ops"
  location            = "eastus"
  resource_group_name = "rg-app"
  sku_name            = "Basic"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.automation.id]
  }
}
