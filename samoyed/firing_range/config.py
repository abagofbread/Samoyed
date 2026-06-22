from __future__ import annotations

import os
from pathlib import Path

# LocalStack defaults (override with env or CLI flags).
DEFAULT_ENDPOINT = os.environ.get("SAMOYED_FIRING_RANGE_ENDPOINT", "http://localhost:4566")
DEFAULT_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
DEFAULT_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "test")
DEFAULT_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "test")

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "firing-range" / "docker-compose.yml"

# Vulnerable lab topology names (created via API, not checked into the repo).
LAB_USER = "leaked-user"
LAB_ADMIN_ROLE = "admin"
LAB_BUCKET = "prod-data"
LAB_SECRET = "prod-db"
LAB_LAMBDA = "vulnerable-handler"
LAB_LAMBDA_ROLE = "lambda-exec"
LAB_WEB_BUCKET = "web-app-assets"

# Bronze medal — orphan noise (listable, not on attack path from leaked-user).
BRONZE_BUCKETS = (
    "logs-archive-2023-q4",
    "tmp-uploads-staging",
    "marketing-exports-dead",
    "cloudtrail-delivery-failed",
    "athena-query-results-scratch",
)
BRONZE_SECRETS = (
    "rotated-api-key-archive",
    "old-slack-webhook",
)
BRONZE_LAMBDAS = (
    "unused-cron-healthcheck",
    "legacy-pdf-thumbnail",
)
BRONZE_IAM_USERS = (
    "billing-exporter-bot",
    "security-hub-invoker",
)
BRONZE_IAM_ROLES = (
    "legacy-monitoring-role",
    "stray-config-auditor",
)
BRONZE_LAMBDA_EXEC_ROLE = "bronze-lambda-exec"
BRONZE_PATH_SECRET = "old-slack-webhook"
BRONZE_CHAIN_SECRET = "rotated-api-key-archive"
BRONZE_PATH_BUCKET = "marketing-exports-dead"
BRONZE_LOAD_BALANCERS = (
    "bronze-public-alb-frontend",
    "bronze-internal-nlb-cache",
)

# Silver medal — realistic platform shape; dev CI/CD does not reach prod.
SILVER_DEV_EKS = "samoyed-dev-eks"
SILVER_PROD_EKS = "samoyed-prod-eks"
SILVER_DEV_PIPELINE = "corp-app-dev-pipeline"
SILVER_PROD_PIPELINE = "corp-app-prod-pipeline"
SILVER_DEV_CICD_ROLE = "dev-cicd-deploy"
SILVER_PROD_CICD_ROLE = "prod-cicd-deploy"
SILVER_DEV_BUILD_ROLE = "dev-codebuild-runner"
SILVER_DEV_BUCKET = "dev-cicd-artifacts"
SILVER_DEV_CONFIG_BUCKET = "dev-k8s-config-snapshots"
SILVER_DEV_SECRET = "dev/hubspot-sandbox-token"
SILVER_PROD_SECRET = "prod/payment-gateway-key"
SILVER_DEV_LAMBDA = "dev-feature-flags-sync"
SILVER_DEV_STAGING_ROLE = "dev-staging-operator"

# Runtime output (gitignored via .samoyed/)
ARTIFACTS_DIR = Path(__file__).resolve().parents[2] / ".samoyed" / "firing-range"
CREDENTIALS_FILE = ARTIFACTS_DIR / "leaked-user-credentials.json"
SCOUTSUITE_DIR = ARTIFACTS_DIR / "scoutsuite"
CLIENT_IAM_REPORT_FILE = ARTIFACTS_DIR / "client-iam-report.json"
AWS_AUTHZ_FILE = ARTIFACTS_DIR / "aws-authz-details.json"
PROBE_REPORT_FILE = ARTIFACTS_DIR / "probe-report.json"
SEED_METADATA_FILE = ARTIFACTS_DIR / "seed-metadata.json"
ACCOUNT_INVENTORY_FILE = ARTIFACTS_DIR / "account-inventory.json"
ARTIFACT_SNAPSHOTS_DIR = ARTIFACTS_DIR / "snapshots"
LATEST_SNAPSHOT_DIR = ARTIFACT_SNAPSHOTS_DIR / "latest"
