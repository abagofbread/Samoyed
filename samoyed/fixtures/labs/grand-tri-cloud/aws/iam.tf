# Illustrative only — not for apply. Grand tri-cloud AWS IAM deltas over corp-mesh-aws.

resource "aws_iam_role_policy" "web_assume_bastion" {
  name = "web_assume_bastion"
  role = "web-role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = ["arn:aws:iam::111111111111:role/bastion-role"]
    }]
  })
}

resource "aws_iam_role" "legacy_monitoring_role" {
  name = "legacy-monitoring-role"
}

resource "aws_s3_bucket" "decoy_cloudtrail_archive" {
  bucket = "corp-decoy-cloudtrail-archive"
}
