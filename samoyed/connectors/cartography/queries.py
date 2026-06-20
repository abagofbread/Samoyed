from __future__ import annotations

# Read-only Cypher used to import Cartography AWS intel into Samoyed concepts.
# Schema reference: https://cartography-cncf.github.io/cartography/modules/aws/schema.html

AWS_ACCOUNTS = """
MATCH (a:AWSAccount)
WHERE $account_id IS NULL OR a.id = $account_id
RETURN a.id AS account_id, a.name AS name
"""

AWS_PRINCIPALS = """
MATCH (a:AWSAccount)
WHERE $account_id IS NULL OR a.id = $account_id
MATCH (a)-[:RESOURCE]->(p)
WHERE p:AWSUser OR p:AWSRole OR p:AWSGroup
RETURN DISTINCT
  p.arn AS arn,
  labels(p) AS labels,
  coalesce(p.name, p.user_name, p.role_name) AS name,
  a.id AS account_id
"""

STS_ASSUME_ROLE_ALLOW = """
MATCH (src)-[:STS_ASSUMEROLE_ALLOW]->(dst:AWSRole)
WHERE src.arn IS NOT NULL AND dst.arn IS NOT NULL
  AND ($account_id IS NULL OR dst.arn CONTAINS $account_id)
RETURN DISTINCT src.arn AS src_arn, dst.arn AS dst_arn
"""

LAMBDA_ASSUMES_ROLE = """
MATCH (l:AWSLambda)-[:ASSUMES]->(r:AWSRole)
WHERE l.arn IS NOT NULL AND r.arn IS NOT NULL
  AND ($account_id IS NULL OR l.arn CONTAINS $account_id)
RETURN DISTINCT l.arn AS lambda_arn, l.name AS name, r.arn AS role_arn
"""

EC2_INSTANCE_PROFILE_ROLE = """
MATCH (i:EC2Instance)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)-[:ASSOCIATED_WITH]->(r:AWSRole)
WHERE r.arn IS NOT NULL
  AND ($account_id IS NULL OR r.arn CONTAINS $account_id)
RETURN DISTINCT
  coalesce(i.instanceid, i.id) AS instance_id,
  i.arn AS instance_arn,
  r.arn AS role_arn
"""

S3_ACCESS = """
MATCH (p)-[rel:CAN_READ|CAN_WRITE]->(b:S3Bucket)
WHERE p.arn IS NOT NULL
  AND ($account_id IS NULL OR p.arn CONTAINS $account_id)
RETURN DISTINCT
  p.arn AS src_arn,
  type(rel) AS access,
  coalesce(b.arn, b.id, b.name) AS bucket_native_id,
  b.name AS bucket_name
"""

SECRETS_MANAGER = """
MATCH (a:AWSAccount)-[:RESOURCE]->(s:SecretsManagerSecret)
WHERE $account_id IS NULL OR a.id = $account_id
RETURN DISTINCT s.id AS arn, s.name AS name, a.id AS account_id
"""

DYNAMODB_ACCESS = """
MATCH (p)-[:CAN_QUERY]->(t:DynamoDBTable)
WHERE p.arn IS NOT NULL
  AND ($account_id IS NULL OR p.arn CONTAINS $account_id)
RETURN DISTINCT p.arn AS src_arn, coalesce(t.arn, t.id, t.name) AS table_id, t.name AS name
"""

K8S_CLUSTER = """
MATCH (c:KubernetesCluster)
RETURN DISTINCT c.id AS cluster_id, c.name AS name
"""

K8S_SA = """
MATCH (c:KubernetesCluster)-[:RESOURCE]->(ns:KubernetesNamespace)-[:RESOURCE]->(sa:KubernetesServiceAccount)
RETURN DISTINCT
  sa.id AS sa_id,
  sa.name AS name,
  ns.name AS namespace,
  c.id AS cluster_id
"""

GCP_SERVICE_ACCOUNTS = """
MATCH (p:GCPProject)-[:RESOURCE]->(sa:GCPServiceAccount)
WHERE $project_id IS NULL OR p.id = $project_id
RETURN DISTINCT sa.email AS email, p.id AS project_id
"""
