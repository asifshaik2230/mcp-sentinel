# MCP-Sentinel

### Enterprise Zero-Trust Agent Firewall for the Model Context Protocol (MCP)

**MCP-Sentinel** is the compliance and control plane for organizations deploying autonomous AI agents against enterprise systems. As agents gain the ability to invoke tools, read files, query data stores, and trigger workflows through MCP, every tool call becomes a privileged security boundary. MCP-Sentinel sits on that boundary—intercepting, inspecting, authorizing, and auditing MCP traffic before it reaches production endpoints.

It is designed for security, platform, and AI engineering teams that need **enforceable policy**, **forensic auditability**, and **board-ready evidence** that agentic workloads do not expand the attack surface beyond what the business has explicitly approved.

---

## Why This Matters Now

Autonomous agents collapse the traditional perimeter: a single compromised prompt, poisoned tool schema, or over-scoped credential can become lateral movement, data exfiltration, or destructive execution. Industry guidance—most notably the **2026 OWASP MCP Top 10**—codifies these risks as first-class categories that regulators, insurers, and enterprise buyers now expect vendors and internal platforms to address.

MCP-Sentinel ships automated mitigation for the highest-impact classes of that taxonomy:

| Risk | OWASP / CVE | Sentinel control |
|------|-------------|------------------|
| **Tool Poisoning** | OWASP **MCP03** | Deep inspection of tool names, descriptions, metadata, and argument payloads for hidden prompt injections (`ignore previous instructions`, `system override`, jailbreak markers) |
| **Command Injection** | OWASP **MCP05** | Blocks unauthorized shell/bash tools and shell-chaining / destructive patterns (`\|`, `&&`, `;`, `rm -rf`) |
| **Excessive Agency** | OWASP **MCP07** | Token-based Fine-Grained Authorization (FGA): each agent identity is scoped to an explicit allow-list of tools |
| **DNS Rebinding** | **CVE-2026-11624** | Strict `Host` + `Origin` validation on the MCP execute path; untrusted or missing origins are rejected and audited |

Every decision—allow or deny—is persisted to an immutable audit trail with timestamp, authenticated agent identity, tool name, status, rejection reason, and full request payload. That trail is what turns “we trust our agents” into **demonstrable control**.

---

## Core Architectural Pillars

### 1. Zero-latency Spring Boot interception proxy
A production-grade **Java 17 / Spring Boot 3** service (`mcp-proxy`) exposes `POST /v1/mcp/execute` as the mandatory chokepoint for MCP tool execution. Servlet filters and a transactional firewall service evaluate each request in-process—no out-of-band round trips required for the MVP policy path—so security does not become a throughput bottleneck for agent loops.

### 2. Dynamic security rule engine
`SecurityRuleEngine` applies layered, regex-backed and schema-aware policies across the serialized JSON payload: blocked tool catalogs, poisoning phrase detection, path-traversal guards (`../`, `/etc/passwd`), and command-injection signatures. Rules emit canonical rejection reasons suitable for SOC dashboards and compliance reports.

### 3. Token-based Fine-Grained Authorization (FGA)
OAuth 2.1–style **Bearer tokens** map to agent identities and scoped tool sets via an in-proxy FGA registry. Client-supplied `agent_id` values cannot spoof identity: the audit trail stamps the **authenticated** agent from the token. Out-of-scope tool attempts return `403` with reason `FGA Scope Violation`; missing or invalid credentials return `401`.

### 4. Real-time Streamlit observability dashboard
`security-dashboard` (Python 3.11 / Streamlit) consumes the proxy’s audit REST API and presents live metrics (total requests, threats blocked, active MCP connections), threat classification, rejection-reason filters, and a full payload-level audit table—purpose-built for security operations and buyer demos.

```
Autonomous Agent
       │  Authorization: Bearer <scoped token>
       │  Origin / Host (trusted allow-list)
       ▼
┌──────────────────────────────────────────────────────────┐
│  mcp-proxy :8080                                         │
│  DnsRebindingFilter → AgentAuthFilter → FirewallService  │
│       │                    │                  │          │
│       │                    │                  ▼          │
│       │                    │         SecurityRuleEngine  │
│       │                    │         + FGA scope check   │
│       ▼                    ▼                  ▼          │
│                 H2 audit store (/data)                   │
└──────────────────────────────────────────────────────────┘
       │
       │  GET /api/audit/logs · /api/audit/metrics
       ▼
┌────────────────────────────┐
│  security-dashboard :8501  │
│  Live SOC / compliance UI  │
└────────────────────────────┘
```

| Service | Technology | Port |
|---------|------------|------|
| `mcp-proxy` | Spring Boot 3.2 · Java 17 · H2 | **8080** |
| `security-dashboard` | Python 3.11 · Streamlit | **8501** |

---

## Quickstart (full stack in ~10 seconds)

**Prerequisites:** Docker Desktop (or Docker Engine + Compose) on Apple Silicon or amd64.

```bash
git clone https://github.com/asifshaik2230/mcp-sentinel.git
cd mcp-sentinel
docker compose up --build
```

| Surface | URL |
|---------|-----|
| Firewall proxy | http://localhost:8080 |
| Security dashboard | http://localhost:8501 |
| Health probe | http://localhost:8080/actuator/health |
| Audit API | http://localhost:8080/api/audit/logs |

**Smoke test (allowed call):**

```bash
curl -s -X POST http://localhost:8080/v1/mcp/execute \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:8080' \
  -H 'Authorization: Bearer tok_agent_alpha_read' \
  -d '{"tool_name":"read_file","arguments":{"path":"/docs/policy.md"},"session_id":"demo-001"}'
```

Open the dashboard to watch the allow/deny stream update in real time.

---

## Default FGA identities (demo registry)

| Bearer token | Agent identity | Allowed tools |
|--------------|----------------|---------------|
| `tok_agent_alpha_read` | `agent-alpha` | `read_file`, `list_dir` |
| `tok_agent_beta_search` | `agent-beta` | `search` |
| `tok_agent_gamma_write` | `agent-gamma` | `write_file` |

Tokens and scopes are configuration-driven (`mcp.sentinel.fga.*` in `application.properties` / environment) and are intended to be replaced by corporate IdP-issued credentials in production deployments.

---

## Acquisition & diligence materials

Technical buyers and diligence teams should start here:

| Document | Purpose |
|----------|---------|
| [`docs/acquisition/architecture_spec.md`](docs/acquisition/architecture_spec.md) | System topology, request lifecycle, data isolation, and security control mapping |
| [`docs/acquisition/growth_roadmap.md`](docs/acquisition/growth_roadmap.md) | Post-acquisition product vectors to expand ARR and defensibility |

---

## Repository layout

```
mcp-sentinel/
├── docker-compose.yml              # One-command orchestration (8080 + 8501)
├── docs/acquisition/               # Diligence & strategy pack
├── mcp-proxy/                      # Spring Boot zero-trust firewall
└── security-dashboard/             # Streamlit observability UI
```

---

## License & commercial positioning

MCP-Sentinel is positioned as a **B2B security control product**: a deployable firewall appliance for MCP, with a clear path from self-hosted Docker MVP to multi-tenant SaaS, IdP-integrated agent provisioning, and ecosystem SDKs. The codebase is intentionally modular—proxy policy plane, auth registry, audit store, and dashboard—so an acquirer can productize, rebrand, and scale without rewriting the core interception model.

For architecture depth and valuation upside, see the acquisition documentation linked above.
