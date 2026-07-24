# Illustrative only — fake subscription IDs, not for apply.

resource "azurerm_virtual_network" "dmz" {
  name                = "vnet-dmz"
  address_space       = ["10.0.0.0/16"]
  location            = "eastus"
  resource_group_name = "rg-dmz"
}

resource "azurerm_subnet" "dmz" {
  name                 = "snet-dmz"
  resource_group_name  = "rg-dmz"
  virtual_network_name = azurerm_virtual_network.dmz.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_virtual_network" "app" {
  name                = "vnet-app"
  address_space       = ["10.10.0.0/16"]
  location            = "eastus"
  resource_group_name = "rg-app"
  # subscription 22222222-2222-2222-2222-222222222222
}

resource "azurerm_subnet" "app" {
  name                 = "snet-app"
  resource_group_name  = "rg-app"
  virtual_network_name = azurerm_virtual_network.app.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_network_security_group" "bastion" {
  name                = "nsg-bastion"
  location            = "eastus"
  resource_group_name = "rg-dmz"

  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "*"
    destination_port_range     = "22"
    destination_address_prefix = "*"
    source_port_range          = "*"
  }
}

resource "azurerm_virtual_network_peering" "dmz_to_app" {
  name                      = "peer-dmz-app"
  resource_group_name       = "rg-dmz"
  virtual_network_name      = azurerm_virtual_network.dmz.name
  remote_virtual_network_id = azurerm_virtual_network.app.id
  allow_virtual_network_access = true
}
