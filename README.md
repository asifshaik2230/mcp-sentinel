# MCP-Sentinel

**Zero-Trust Agent Firewall** for Model Context Protocol (MCP) traffic — intercept, inspect, and audit tool calls between autonomous AI agents and enterprise endpoints.

## Architecture

| Service | Stack | Port |
|---------|--------|------|
| `mcp-proxy` | Spring Boot 3.2 · Java 17 · H2 | `8080` |
| `security-dashboard` | Python 3.11 · Streamlit | `8501` |

```
AI Agent  ──POST /v1/mcp/execute──►  mcp-proxy (rule engine + audit)
                                         │
                                         ▼
                              H2 audit DB  (/data)
                                         │
                          GET /api/audit/*│
                                         ▼
                              security-dashboard (Streamlit)
```

### Security rules (MVP)

1. **RULE 1** — Block tools named `bash`, `shell`, or `execute_command` → `403 Forbidden`
2. **RULE 2** — Block payloads matching shell chaining / injection patterns (`|`, `&&`, `;`, `rm -rf`, common jailbreak phrases)

Every request is written to the audit trail as `ALLOWED` or `BLOCKED`.

## Quick start (Docker — Apple Silicon friendly)

> The proxy runtime image uses `eclipse-temurin:17-jre-jammy` (multi-arch arm64/amd64). Temurin’s Alpine JRE tag does not publish arm64 manifests, so Jammy is used for reliable Apple Silicon builds.

```bash
docker compose up --build
```

- Proxy: http://localhost:8080  
- Dashboard: http://localhost:8501  

## Try it

**Allowed request**

```bash
curl -s -X POST http://localhost:8080/v1/mcp/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "tool_name": "read_file",
    "arguments": {"path": "/docs/policy.md"},
    "agent_id": "agent-alpha",
    "session_id": "sess-001"
  }'
```

**Blocked — dangerous tool (RULE 1)**

```bash
curl -s -X POST http://localhost:8080/v1/mcp/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "tool_name": "bash",
    "arguments": {"command": "ls -la"},
    "agent_id": "agent-alpha",
    "session_id": "sess-001"
  }'
```

**Blocked — injection pattern (RULE 2)**

```bash
curl -s -X POST http://localhost:8080/v1/mcp/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "tool_name": "search",
    "prompt": "list files && rm -rf /tmp/x",
    "agent_id": "agent-beta",
    "session_id": "sess-002"
  }'
```

**Audit APIs** (used by the dashboard)

```bash
curl -s http://localhost:8080/api/audit/metrics | jq
curl -s http://localhost:8080/api/audit/logs | jq
```

## Local development

### Proxy

```bash
cd mcp-proxy
mvn spring-boot:run
```

### Dashboard

```bash
cd security-dashboard
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PROXY_BASE_URL=http://localhost:8080 streamlit run app.py
```

### Unit tests

```bash
cd mcp-proxy && mvn test
```

## Project layout

```
mcp-sentinel/
├── docker-compose.yml
├── mcp-proxy/                 # Spring Boot firewall
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/java/...
└── security-dashboard/        # Streamlit observability UI
    ├── Dockerfile
    ├── requirements.txt
    └── app.py
```
