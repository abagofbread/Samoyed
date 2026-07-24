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

GCP_PROJECTS = """
MATCH (p:GCPProject)
WHERE $project_id IS NULL OR p.id = $project_id
RETURN DISTINCT p.id AS project_id, coalesce(p.name, p.id) AS name
"""

GCP_BUCKETS = """
MATCH (b:GCSBucket)
OPTIONAL MATCH (p:GCPProject)-[:RESOURCE]->(b)
WHERE $project_id IS NULL OR p.id = $project_id OR b.projectid = $project_id
RETURN DISTINCT coalesce(b.name, b.id) AS name, coalesce(p.id, b.projectid) AS project_id
"""

GCP_SECRETS = """
MATCH (s:GCPSecret)
OPTIONAL MATCH (p:GCPProject)-[:RESOURCE]->(s)
WHERE $project_id IS NULL OR p.id = $project_id
RETURN DISTINCT coalesce(s.name, s.id) AS name, coalesce(p.id, s.projectid) AS project_id
"""

GCP_INSTANCES = """
MATCH (i:GCPInstance)
OPTIONAL MATCH (p:GCPProject)-[:RESOURCE]->(i)
WHERE $project_id IS NULL OR p.id = $project_id
RETURN DISTINCT
  coalesce(i.id, i.name) AS instance_id,
  coalesce(i.serviceaccountemail, i.email) AS sa_email,
  coalesce(p.id, i.projectid) AS project_id
"""

EC2_NETWORK_PLACEMENT = """
MATCH (i:EC2Instance)
WHERE $account_id IS NULL OR coalesce(i.arn, '') CONTAINS $account_id
OPTIONAL MATCH (i)-[:PART_OF_SUBNET]->(sn:EC2Subnet)-[:MEMBER_OF_AWS_VPC]->(v:AWSVpc)
OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
WITH i, v,
  collect(DISTINCT sn.id) AS subnet_ids,
  collect(DISTINCT sg.id) AS sg_ids
RETURN DISTINCT
  coalesce(i.instanceid, i.id) AS instance_id,
  i.arn AS instance_arn,
  coalesce(v.id, i.vpcid) AS vpc_id,
  subnet_ids,
  sg_ids,
  coalesce(i.privateipaddress, i.private_ip_address) AS private_ip,
  coalesce(i.publicipaddress, i.public_ip_address) AS public_ip,
  coalesce(i.exposed_internet, false) AS exposed_internet
"""

AWS_VPC_CIDRS = """
MATCH (v:AWSVpc)
OPTIONAL MATCH (v)-[:BLOCK_ASSOCIATION]->(c:AWSCidrBlock)
WITH v, collect(DISTINCT coalesce(c.cidr_block, c.id)) AS cidrs
RETURN DISTINCT v.id AS vpc_id, cidrs, v.cidr_block_association_set AS assoc
"""

AWS_PEERING_CONNECTIONS = """
MATCH (pcx:AWSPeeringConnection)
OPTIONAL MATCH (pcx)-[:REQUESTER_VPC]->(req:AWSVpc)
OPTIONAL MATCH (pcx)-[:ACCEPTER_VPC]->(acc:AWSVpc)
OPTIONAL MATCH (pcx)-[:REQUESTER_CIDR]->(rc:AWSCidrBlock)
OPTIONAL MATCH (pcx)-[:ACCEPTER_CIDR]->(ac:AWSCidrBlock)
OPTIONAL MATCH (req_acct:AWSAccount)-[:RESOURCE]->(req)
OPTIONAL MATCH (acc_acct:AWSAccount)-[:RESOURCE]->(acc)
RETURN DISTINCT
  coalesce(pcx.id, pcx.arn) AS peering_id,
  coalesce(pcx.status_code, pcx.status, 'active') AS status,
  coalesce(req.id, pcx.requestervpcid) AS local_vpc_id,
  coalesce(acc.id, pcx.acceptervpcid) AS remote_vpc_id,
  coalesce(req_acct.id, pcx.requesterownerid) AS local_account_id,
  coalesce(acc_acct.id, pcx.accepterownerid) AS remote_account_id,
  collect(DISTINCT coalesce(rc.cidr_block, rc.id)) AS local_cidrs,
  collect(DISTINCT coalesce(ac.cidr_block, ac.id)) AS remote_cidrs
"""

EC2_SG_INGRESS = """
MATCH (sg:EC2SecurityGroup)
OPTIONAL MATCH (r:IpRange)-[:MEMBER_OF_IP_RULE]->(rule:IpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
OPTIONAL MATCH (src_sg:EC2SecurityGroup)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(rule)
WITH sg, rule,
  collect(DISTINCT r.id) AS cidrs,
  collect(DISTINCT src_sg.id) AS referenced_sg_ids
WHERE rule IS NOT NULL OR size(cidrs) > 0
RETURN DISTINCT
  sg.id AS sg_id,
  cidrs,
  referenced_sg_ids,
  rule.fromport AS from_port,
  rule.toport AS to_port,
  rule.protocol AS protocol
"""
