from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from samoyed.firing_range import aws_helpers
from samoyed.firing_range.config import (
    LAB_INTERNAL_WRITER_ROLE,
    LAB_PCI_BUCKET,
    LAB_PCI_SCOPE,
    LAB_PUBLIC_UPLOADS_BUCKET,
    LAB_SSRF_LAMBDA,
    LAB_SSRF_ROLE,
)


def seed_ssrf_pci_lab(
    *,
    iam: Any,
    s3: Any,
    lambda_client: Any,
    account: str,
    region: str,
) -> dict[str, Any]:
    """
    SSRF-vulnerable Lambda with public URL → metadata creds → STS assume role → PCI bucket write.
    Also seeds a staging bucket that is not internet-writable until a proposed change opens it.
    """
    aws_helpers.ensure_bucket(s3, LAB_PCI_BUCKET, region=region)
    aws_helpers.ensure_bucket(s3, LAB_PUBLIC_UPLOADS_BUCKET, region=region)

    writer_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    writer_arn = aws_helpers.ensure_role(iam, LAB_INTERNAL_WRITER_ROLE, writer_trust)
    writer_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:DeleteObject"],
                "Resource": f"arn:aws:s3:::{LAB_PCI_BUCKET}/*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=LAB_INTERNAL_WRITER_ROLE,
        PolicyName="pci-writer",
        PolicyDocument=json.dumps(writer_policy),
    )

    ssrf_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    ssrf_role_arn = aws_helpers.ensure_role(iam, LAB_SSRF_ROLE, ssrf_trust)
    assume_internal = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": writer_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=LAB_SSRF_ROLE,
        PolicyName="assume-internal-writer",
        PolicyDocument=json.dumps(assume_internal),
    )

    lambda_arn = _ensure_ssrf_lambda(lambda_client, role_arn=ssrf_role_arn, region=region)
    try:
        lambda_client.create_function_url_config(
            FunctionName=LAB_SSRF_LAMBDA,
            AuthType="NONE",
            Cors={"AllowOrigins": ["*"], "AllowMethods": ["GET", "POST"]},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise

    return {
        "ssrf_lambda": lambda_arn,
        "ssrf_role_arn": ssrf_role_arn,
        "internal_writer_role_arn": writer_arn,
        "pci_bucket": LAB_PCI_BUCKET,
        "staging_bucket": LAB_PUBLIC_UPLOADS_BUCKET,
        "pci_scope": LAB_PCI_SCOPE,
        "hint": (
            "SSRF fetcher exposes metadata chain to internal-data-writer → pci-internal-ledger. "
            "Use POST /api/sessions/{ref}/changes/analyze to test opening public-uploads-staging."
        ),
    }


def _ensure_ssrf_lambda(lambda_client: Any, *, role_arn: str, region: str) -> str:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            (
                "import urllib.request\n"
                "def handler(event, context):\n"
                "    url = (event or {}).get('url', 'http://169.254.169.254/latest/meta-data/iam/')\n"
                "    return {'statusCode': 200, 'body': urllib.request.urlopen(url, timeout=2).read()}\n"
            ),
        )
    payload = buf.getvalue()
    try:
        resp = lambda_client.create_function(
            FunctionName=LAB_SSRF_LAMBDA,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": payload},
            Description="Intentionally SSRF-vulnerable URL fetcher (LocalStack lab)",
        )
        return resp["FunctionArn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise
        return lambda_client.get_function(FunctionName=LAB_SSRF_LAMBDA)["Configuration"]["FunctionArn"]
