# Samoyed firing range

Emulated vulnerable clouds for local attack-path practice. Topology is created at runtime via cloud APIs — nothing sensitive is checked in.

Inspired by [AWSGoat](https://github.com/ine-labs/AWSGoat)-style scenarios (leaked keys, role assumption, Lambda execution roles, privesc patterns), but runs entirely on **LocalStack**.

## Quick start

```bash
# Start LocalStack
samoyed firing-range up

# Seed AWSGoat-like lab + write leaked-user access keys
samoyed firing-range seed

# Verify all three ingestion paths (client report, probes, ScoutSuite)
pip install 'samoyed[firing-range]'   # optional: ScoutSuite CLI
samoyed firing-range verify
```

## What gets seeded

| Resource | Purpose |
|----------|---------|
| IAM user `leaked-user` | Compromised caller; access key written to `.samoyed/firing-range/leaked-user-credentials.json` |
| IAM role `admin` | `AdministratorAccess`; trust allows `leaked-user` to assume |
| Inline `assume-admin` | `sts:AssumeRole` → admin |
| Inline `self-attach` | `iam:AttachUserPolicy` on self (privesc pattern) |
| Inline `recon-read` | Realistic read APIs for client report + probes (`s3:ListBuckets`, `secretsmanager:ListSecrets`, …) |
| S3 `prod-data`, `web-app-assets` | Data-store targets |
| Secret `prod-db` | Secret-store target |
| Lambda `vulnerable-handler` | Runtime binding via `lambda-exec` role with secret read |

Account ID comes from LocalStack (typically `000000000000`).

## Three test workflows (real tool output)

### 1. Client sends IAM report

Simulates a Samoyed agent running on a compromised host with the leaked key. Collects **live API responses** (not hand-authored JSON):

```bash
samoyed firing-range client-report
# → .samoyed/firing-range/client-iam-report.json

# Import into Samoyed (API or programmatic)
curl -F connector=iam-report -F file=@.samoyed/firing-range/client-iam-report.json \
  http://localhost:8000/api/sessions/import
```

### 2. Leaked API key + probe catalog

Tests the probe/brute-force data source against LocalStack with the leaked key:

```bash
samoyed firing-range probe-leaked
samoyed firing-range probe-leaked --report-only   # raw ProbeReport JSON
```

Expected allowed ops include `sts:GetCallerIdentity`, `s3:ListBuckets`, `secretsmanager:ListSecrets`. Denied ops are logged for analyst review.

### 3. Real IAM analysis tool output (aws-authz-details)

Exports **`iam:GetAccountAuthorizationDetails`** — the same AWS API that PMapper, CloudMapper, and IAM analyzers consume. Works reliably against LocalStack:

```bash
samoyed firing-range export-aws-authz --import
```

ScoutSuite against LocalStack requires a proxy ([Aerides](https://github.com/ncc-erik-steringer/Aerides)); on real AWS:

```bash
pip install scoutsuite   # or: samoyed firing-range scoutsuite --docker
samoyed firing-range scoutsuite
```

## Integration tests

With LocalStack running and seeded:

```bash
samoyed firing-range up && samoyed firing-range seed
pip install scoutsuite
pytest tests/test_firing_range.py -m integration -v
```

Unit tests (mocked, no Docker):

```bash
pytest tests/test_firing_range.py tests/test_client_iam_report.py -m "not integration"
```

## Offline vs emulated

| Mode | Use when |
|------|----------|
| `samoyed import-fixture lab-aws` | UI/tests without Docker — field report JSON via connector pipeline |
| `samoyed firing-range *` | Live enum, probes, client reports, ScoutSuite against LocalStack |

## Teardown

```bash
samoyed firing-range down
```
