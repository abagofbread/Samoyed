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

# Runtime output (gitignored via .samoyed/)
ARTIFACTS_DIR = Path(__file__).resolve().parents[2] / ".samoyed" / "firing-range"
CREDENTIALS_FILE = ARTIFACTS_DIR / "leaked-user-credentials.json"
SCOUTSUITE_DIR = ARTIFACTS_DIR / "scoutsuite"
CLIENT_IAM_REPORT_FILE = ARTIFACTS_DIR / "client-iam-report.json"
AWS_AUTHZ_FILE = ARTIFACTS_DIR / "aws-authz-details.json"
