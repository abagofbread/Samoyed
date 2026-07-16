# Samoyed

BloodHound for cloud — ingest identity and resource data, build an attack-path graph, and query blast radius from leaked credentials, compromised workloads, and supply-chain pivots. Very much a work in progress, user beware.

## Features (v0.1)

- Live AWS enumeration from profiles or key files (permission-bounded)
- Provider-agnostic concept ontology (AWS, GCP, Azure, K8s, Docker — extensible)
- Attack-path search with evidence-backed edges
- `leaked-credential` scenario
- FastAPI + interactive graph UI (force-directed, path highlighting)
- MCP server for Cursor/Claude agent queries
- `.samoyed/` extension workspace for custom enumerators
- **Cartography connector** — import Lyft/CNCF [Cartography](https://github.com/cartography-cncf/cartography) Neo4j graphs for attack-path analysis

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"
pre-commit install     # gitleaks: block secrets before commit
docker compose up -d   # optional Neo4j persistence
```

## Usage

```bash
# Offline demo reports (field-realistic iam-report / cloudfox / authz JSON — no cloud account)
samoyed import-fixture lab-aws
samoyed scenario leaked-credential --session-id fixture-lab-aws

samoyed import-fixture k8s-lab
samoyed scenario compromised-sa --session-id fixture-k8s-lab

samoyed import-fixture enterprise-aws   # multi-hop corp environment
samoyed import-fixture host-pivot        # compromised laptop → cloud creds
samoyed import-fixture cicd-supply-chain # supply-chain dependency marking demo

# List bundled fixtures
samoyed import-fixture --list

# Emulated vulnerable AWS lab (LocalStack — no lab data in repo)
samoyed firing-range up
samoyed firing-range seed
samoyed firing-range enum
# See firing-range/README.md

# Live GCP (service account JSON or ADC + pip install 'samoyed[gcp]')
samoyed enum --provider gcp --key-file sa.json
samoyed whoami --provider gcp

# Live Azure (az login or SP env vars + pip install 'samoyed[azure]')
samoyed enum --provider azure
samoyed whoami --provider azure

# Live Kubernetes enumeration (requires kubeconfig + pip install 'samoyed[k8s]')
samoyed enum --provider kubernetes
samoyed whoami --provider kubernetes

# Live enumeration (IAM/RBAC APIs when available)
samoyed enum --profile attacker

# Leaked key without IAM list access — brute-force API probes
samoyed probe --key-file leaked-aws.json
samoyed probe --list                              # show probe catalog
samoyed probe --key-file leaked.json --report-only  # JSON report only
samoyed enum --probe-only --key-file leaked.json    # probe → graph session
samoyed enum --with-probe --key-file leaked.json    # probe + IAM enum

# Optional custom probes: .samoyed/probes.json

# Import Cartography asset graph (read-only Neo4j; separate from Samoyed session DB)
export CARTOGRAPHY_NEO4J_URI=bolt://localhost:7687
samoyed cartography-status
samoyed import-cartography --caller-arn arn:aws:iam::123456789012:user/alice --account-id 123456789012
samoyed scenario leaked-credential --session-id <session-id>

# Full scenario (enum + blast-radius paths)
samoyed scenario leaked-credential --profile attacker

# Query paths for a session
samoyed paths <session-id> --target-concept SecretStore

# Web UI + API
export SAMOYED_PASSWORD='choose-a-strong-password'
samoyed ui
# Open http://127.0.0.1:8000 — sign in at /login
# Binding beyond localhost auto-generates a password if none is set

# MCP server (add to Cursor MCP config)
samoyed mcp

# Scaffold custom extension
samoyed init-extension enumerator my_custom_api
samoyed init-extension connector my_graph_source
```

## MCP config (Cursor)

```json
{
  "mcpServers": {
    "samoyed": {
      "command": "samoyed",
      "args": ["mcp"]
    }
  }
}
```

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEO4J_URI` | — | Optional Neo4j bolt URI |
| `NEO4J_USER` | `neo4j` | Neo4j user |
| `NEO4J_PASSWORD` | `samoyed-dev` | Neo4j password |
| `CARTOGRAPHY_NEO4J_URI` | falls back to `NEO4J_URI` | Cartography sync database |
| `CARTOGRAPHY_NEO4J_USER` | falls back to `NEO4J_USER` | Cartography Neo4j user |
| `CARTOGRAPHY_NEO4J_PASSWORD` | falls back to `NEO4J_PASSWORD` | Cartography Neo4j password |
| `CARTOGRAPHY_NEO4J_DATABASE` | `neo4j` | Cartography Neo4j database name |
| `SAMOYED_USERNAME` | `admin` | Web UI login username |
| `SAMOYED_PASSWORD` | — | Web UI login password (enables auth when set) |
| `SAMOYED_API_TOKEN` | — | Optional bearer token for API clients |
| `SAMOYED_SECRET_KEY` | random per process | Session signing secret (set in production) |
| `SAMOYED_HOME` | `~/.samoyed` | Data root for persisted sessions |
| `SAMOYED_SESSION_DIR` | `$SAMOYED_HOME/sessions` | Override session storage directory |

## Development

```bash
pytest
ruff check samoyed tests
```

See [AGENTS.md](AGENTS.md) for extension cookbook.
