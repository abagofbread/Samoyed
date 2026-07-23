# Samoyed — extension cookbook for AI agents

Samoyed maps cloud and orchestration identity/trust into an attack-path graph. Extend it by emitting **`ConceptArtifact`** objects — never write to the graph directly.

## Quick start

```bash
pip install -e ".[dev]"
docker compose up -d   # optional Neo4j
samoyed enum --profile myprofile
samoyed scenario leaked-credential --session-id <id>
samoyed mcp            # stdio MCP for Cursor agents
samoyed init-extension enumerator my_internal_api
samoyed init-extension connector my_graph_source
```

## Network reachability (VPC peering / SG-lite)

Samoyed models **network attack paths** without VPC/SG graph nodes. Collectors feed a portable **`NetworkInventory`** (placements, peerings, SG ingress, VPC CIDRs); enrichment emits:

- `The Internet -CAN_REACH->` internet-exposed compute
- compute `-CAN_REACH->` compute (same VPC / peered, SG-lite)
- compute `-VPC_PEERS-> Account:{id}` then unlabeled `BRIDGES_TO` into peer-account resources (best-effort graft from other sessions)

Sources: live AWS enum, Cartography, **Terraform tfstate** (primary offline path), `network-inventory` JSON, optional iam-report `"network"` block.

```bash
samoyed import-fixture vpc-peering-aws   # small cross-account peer demo
samoyed import-fixture corp-mesh-aws     # DMZ/App/PCI + shared/staging mesh (ALBs, buckets)
samoyed import-path ./infra/terraform.tfstate
samoyed import-path ./network.json --attach-to <session>
samoyed scenario can-reach-other-accounts
```

UI: **Network Edges (All)** toolbar toggle (off by default; VPC_PEERS / BRIDGES_TO always shown).

## Cartography connector

Import an existing [Cartography](https://github.com/cartography-cncf/cartography) Neo4j graph (AWS IAM, S3, Lambda, Secrets Manager, GCP SAs, K8s) into a Samoyed session:

```bash
export CARTOGRAPHY_NEO4J_URI=bolt://localhost:7687
samoyed cartography-status
samoyed import-cartography --caller-arn arn:aws:iam::123456789012:user/alice --account-id 123456789012
```

REST: `POST /api/sessions/cartography`, `GET /api/connectors/cartography/status`.

## Web UI authentication

Set `SAMOYED_PASSWORD` before starting the UI (default username `admin` via `SAMOYED_USERNAME`). The login screen protects `/` and all `/api/*` routes except `/api/health` and `/api/auth/*`. Programmatic clients can send `Authorization: Bearer $SAMOYED_API_TOKEN` instead of cookie login.

```bash
export SAMOYED_PASSWORD='your-password'
samoyed ui
```

If you bind to a non-localhost address without credentials, `samoyed ui` generates a random password and prints it to stderr.

## Firing range (emulated clouds)

Vulnerable lab topology is **not** stored in the repo. Use LocalStack + API seeding:

```bash
samoyed firing-range up
samoyed firing-range seed
samoyed firing-range enum
```

See [firing-range/README.md](firing-range/README.md). Offline demos use bundled field report fixtures (`import-fixture`) imported through the connector pipeline.

## Extension boundary

Implement `ConceptEnumerator` in `.samoyed/enumerators/my_enum.py`:

```python
class MyInternalApiEnumerator:
    concept = ConceptType.IDENTITY
    name = "my-internal-api"

    def enumerate(self, ctx: EnumContext) -> Iterator[ConceptArtifact]:
        yield ConceptArtifact(
            concept_type=ConceptType.IDENTITY,
            provider=CloudProvider.AWS,
            native_id="internal:user:123",
            scope_id=ctx.scope.scope_id,
            properties={"native_kind": "InternalUser"},
            evidence=Evidence("internal-api", {"endpoint": "/users/123"}),
        )
```

## L1 concepts

| Concept | Use |
|---------|-----|
| Identity | Users, roles, service accounts |
| Entitlement | Policy statements, RBAC bindings |
| Trust | Assume-role, impersonation |
| RuntimeBinding | EC2, Lambda, pod→node cloud identity |
| Workload | Pods, containers |
| SecretStore / DataStore | High-value targets |
| RegistryStore / ImageProvenance | Supply chain |

## MCP tools

- `list_sessions`, `get_session_summary`
- `list_markings`, `mark_nodes`, `mark_from_alert` — declare compromised starts and crown-jewel targets
- `find_attack_paths`, `get_blast_radius`
- `search_nodes`, `run_scenario` (incl. `can-reach-other-accounts` for VPC peering)
- Resource: `samoyed://ontology`

Mark nodes over MCP (session_id optional — defaults to most recent):

```json
mark_nodes('["arn:aws:iam::123:user/jane"]', compromised=true)
mark_nodes('["prod-db", "corp-vault"]', high_value=true)
mark_from_alert('{"compromised":["arn:..."], "high_value":["prod-db"]}')
```

Declare controlling dependencies (compromise propagates dependency → dependent):

```python
declare_relationship(dependent="build-pipeline", dependency="artifact-bucket")
declare_relationship(dependent="prod-workloads", dependency="build-pipeline")
mark_nodes('["leaked-dev"]', compromised=True)
# WRITES taints bucket; DEPENDS_ON chains to pipeline and prod
```

`PULLS_FROM` / `USES_IMAGE` remain factual enum edges; use `DEPENDS_ON` for analyst supply-chain control points.

Start aliases: `caller`, `host`, `compromised`. Target alias: `target_concept=high_value`.

## API access probing (bug bounty / low-priv keys)

When credentials cannot list IAM/RBAC policies, use **`samoyed probe`** to attempt high-value API calls and infer access from successes:

```bash
samoyed probe --key-file leaked.json
samoyed probe --provider gcp --key-file sa.json
samoyed probe --provider azure
```

Successful probes become graph nodes and `READS`/`WRITES` edges with `discovered_via: probe`. Add custom operations in `.samoyed/probes.json`.

## Common patterns

1. **Leaked cloud key** — start at caller Identity, traverse READS/EXECUTES/CAN_ASSUME_ROLE to SecretStore
2. **Compromised pod** — start Workload → CAN_ESCAPE_TO (mechanism-labeled, one edge per technique: privileged/SYS_PTRACE/hostPath/docker.sock) → node RuntimeBinding → PROJECTS_TO cloud role. Container escapes are transitive edges, not intermediate nodes; IMDS/SSRF credential theft is a CAN_ESCAPE_TO edge straight to the execution role.
3. **Supply chain** — RegistryStore write → ImageProvenance → USES_IMAGE ← Workloads → SA secrets

## REST API

OpenAPI at `/openapi.json` when running `samoyed ui`.
