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

See [firing-range/README.md](firing-range/README.md). Offline `load-sample` graphs remain for UI/tests only.

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
| EscapeSurface | Privileged, hostPath, docker.sock |
| SecretStore / DataStore | High-value targets |
| RegistryStore / ImageProvenance | Supply chain |

## MCP tools

- `list_sessions`, `get_session_summary`
- `find_attack_paths`, `get_blast_radius`
- `search_nodes`, `run_scenario`
- Resource: `samoyed://ontology`

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
2. **Compromised pod** — start Workload → HAS_ESCAPE_SURFACE → CAN_ESCAPE_TO → node RuntimeBinding → PROJECTS_TO cloud role
3. **Supply chain** — RegistryStore write → ImageProvenance → USES_IMAGE ← Workloads → SA secrets

## REST API

OpenAPI at `/openapi.json` when running `samoyed ui`.
