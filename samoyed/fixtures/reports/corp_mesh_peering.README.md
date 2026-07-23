# corp-mesh-aws Terraform fixture

Offline attack-path lab imported via:

```bash
samoyed import-fixture corp-mesh-aws
samoyed scenario can-reach-other-accounts
```

## Topology

| VPC | CIDR | Account | Role |
|-----|------|---------|------|
| `vpc-dmz001` | 10.0.0.0/16 | 111111111111 | Internet edge (public ALB, bastion, web) |
| `vpc-app001` | 10.10.0.0/16 | 111111111111 | Application tier (internal ALB, APIs, workers) |
| `vpc-pci001` | 10.20.0.0/16 | 111111111111 | PCI data (DB + ETL + Lambda) |
| `vpc-shared001` | 10.30.0.0/16 | 222222222222 | Shared CI/CD + logging |
| `vpc-staging001` | 10.40.0.0/16 | 333333333333 | Staging (risky DMZ peer) |

### Peerings

- DMZ ↔ App (same account)
- App ↔ PCI (same account)
- App ↔ Shared (cross-account)
- DMZ ↔ Staging (cross-account)

### Notable starts / targets

- **Caller:** `bastion` (`i-dmzbastion01`) — public IP + open SSH SG + instance role
- **Internet edge:** `corp-public-alb` → web-1/web-2
- **Crown jewels:** `corp-pci-backups`, `pci-db-*`, `pci-etl`
- **Supply chain:** `shared-cicd-artifacts`, `cicd-runner-*`

Regenerate the `.tfstate` by re-running the generator embedded in the commit history / agent session if needed; the fixture file is the source of truth for demos.
