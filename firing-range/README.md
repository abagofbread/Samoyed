# Samoyed firing range

Emulated vulnerable clouds for local attack-path practice. **Nothing is checked into this repo except compose + seed code** — topology is created at runtime via cloud APIs.

## Quick start (AWS / LocalStack)

```bash
# Start emulated AWS (pulls LocalStack image on first run)
samoyed firing-range up

# Seed vulnerable IAM + S3 + Secrets Manager topology
samoyed firing-range seed

# Enumerate the emulated account into a Samoyed session
samoyed firing-range enum

# Run blast-radius scenario on the live-emulated graph
samoyed scenario leaked-credential --session-id <id-from-enum>
```

Or manually:

```bash
docker compose -f firing-range/docker-compose.yml up -d
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://localhost:4566
samoyed firing-range seed
samoyed enum --provider aws
```

## What gets seeded

| Resource | Purpose |
|----------|---------|
| IAM user `leaked-user` | Low-priv caller; can `sts:AssumeRole` into admin |
| IAM role `admin` | Broad access (AdministratorAccess) |
| Inline `iam:AttachUserPolicy` on self | Privesc pattern (matches offline `sample-lab`) |
| S3 bucket `prod-data` | Data-store target |
| Secret `prod-db` | Secret-store target |

Account ID comes from the emulator (LocalStack typically uses `000000000000`).

## Offline vs emulated

| Mode | Use when |
|------|----------|
| `samoyed load-sample` | UI/tests without Docker |
| `samoyed firing-range *` | Live enum + probes against emulated APIs |

Offline samples are tiny Python graph builders in `samoyed/graph/sample*.py` — not firing-range data dumps.

## Kubernetes (bring your own)

For a vulnerable cluster, use an external lab (e.g. [kind](https://kind.sigs.k8s.io/), [k8s-goat](https://github.com/bridgecrewio/K8s-goat)) and point Samoyed at it:

```bash
samoyed enum --provider kubernetes --kubeconfig ~/.kube/config --context kind-samoyed-lab
```

No cluster manifests live in this repo.

## Teardown

```bash
samoyed firing-range down
```
