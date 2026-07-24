# AzureGoat starter target

Use [ine-labs/AzureGoat](https://github.com/ine-labs/AzureGoat) the same way AWSGoat / GCPGoat live under `.samoyed/`.

```bash
git clone https://github.com/ine-labs/AzureGoat.git .samoyed/AzureGoat
# optional live deploy (needs Azure subscription + az login):
# terraform -chdir=.samoyed/AzureGoat apply

# Offline / post-apply import into Samoyed:
samoyed import-path .samoyed/AzureGoat
# or:
samoyed import-path .samoyed/AzureGoat/terraform.tfstate
```

With Azure credentials configured (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` /
`AZURE_CLIENT_SECRET` / subscription), live enum works:

```bash
samoyed enum --provider azure
samoyed scenario leaked-credential --session-id <id>
```

AzureGoat modules surface App Service / Function misconfigurations, Key Vault
and storage exposure, and managed-identity privilege paths. Attack manuals live
upstream in the repo.

`.samoyed/` is gitignored — do not commit the clone.
