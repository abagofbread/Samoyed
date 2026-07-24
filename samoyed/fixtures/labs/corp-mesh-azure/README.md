# Corp mesh Azure lab

Illustrative multi-subscription topology: a DMZ VNet in subscription
`11111111-1111-1111-1111-111111111111` peers into an App/PCI VNet in
`22222222-2222-2222-2222-222222222222`. An internet-facing bastion VM runs with a
user-assigned managed identity that can control an App Service; that app’s MI
reads a Key Vault crown-jewel secret. An Automation Account holds an Owner-ish
RBAC path for privilege-escalation demos, plus storage and ACR stubs.

Use the bundled `corp_mesh_azure.tfstate` for a self-contained importer demo:

```bash
samoyed import-fixture corp-mesh-azure
```

These `.tf` files are valid-looking reference infrastructure and should **not**
be applied as production configuration (fake subscription IDs).
