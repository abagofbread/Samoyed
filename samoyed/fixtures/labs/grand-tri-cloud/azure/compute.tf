# Illustrative only — grand tri-cloud Azure compute expansion.

resource "azurerm_linux_virtual_machine" "workstation" {
  name = "vm-ws-alice"
  # subnet snet-workstations in vnet-dmz (sub 1111...)
}

resource "azurerm_linux_virtual_machine" "app_server" {
  name = "vm-app-api-01"
  # subnet snet-app in vnet-app (sub 2222...)
}

resource "azurerm_storage_account" "devdumps" {
  name = "corpdevdumps"
}

resource "azurerm_storage_account" "staginglogs" {
  name = "corpstaginglogs"
}
