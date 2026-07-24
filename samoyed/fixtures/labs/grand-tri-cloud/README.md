# Grand tri-cloud lab

Patient-zero story built on **corp-mesh-aws**, bridged into **corp-mesh-gcp** and an expanded Azure mesh via companion `enrichment.json` files.

## Attack narrative

1. **Internet → AWS DMZ web** (`web-role` on `web-1` / edge-proxy)
2. **`web-role` `sts:AssumeRole` → `bastion-role`** (subnet/account still AWS DMZ / `111111111111`)
3. **Bastion role material** unlocks GCP `app-deploy@proj-app` (cloud boundary)
4. **GCP** `app-deploy` → TokenCreator → `cloudbuild@proj-shared` → PCI reader / crown GCS (project + VPC peer boundaries)
5. **Parallel branch:** AWS `app-worker-1` weak Azure SP → Website Contributor on `app-corp-api` → app MI → Key Vault (subscription + VNet peer boundaries)

Dummy dead ends: decoy S3, Stripe/Datadog/Slack keys, staging scratch SA, batch MI → staging logs only.

## Layout

```text
grand-tri-cloud/
  aws/   terraform.tfstate + iam.tf + enrichment.json
  gcp/   terraform.tfstate + *.tf + enrichment.json
  azure/ terraform.tfstate + *.tf + enrichment.json
```

## Import (verifies enrichment autoload)

```bash
# Directory import merges all *.tfstate and applies every enrichment.json found
samoyed import-path samoyed/fixtures/labs/grand-tri-cloud

# Or via fixture registry (same pipeline)
samoyed import-fixture grand-tri-cloud
```

Per-environment import also works:

```bash
samoyed import-path samoyed/fixtures/labs/grand-tri-cloud/aws
```
