# MCP-Sentinel — Architecture Specification

**Document type:** Technical due diligence  
**Product:** MCP-Sentinel — Enterprise Zero-Trust Agent Firewall for MCP  
**Audience:** Acquiring engineering, security, and product diligence teams  
**Stack (current):** Spring Boot 3.2 / Java 17 · H2 · Python 3.11 / Streamlit · Docker Compose  

---

## 1. Purpose

This specification describes the production topology of MCP-Sentinel as shipped in the repository, the end-to-end lifecycle of an MCP tool-execution request, the security control mapping to OWASP MCP Top 10 / CVE-2026-11624, and the data isolation properties of the MVP deployment. It is intended to answer the questions enterprise buyers ask during technical audit: *Where does trust begin? What is enforced? What is logged? What can one tenant or agent see?*

---

## 2. System topology

### 2.1 Logical components

| Component | Role | Runtime | Network exposure |
|-----------|------|---------|------------------|
| **mcp-proxy** | Policy enforcement point (PEP) for MCP execute traffic; audit writer; metrics API | Spring Boot JAR in container | Host `8080` → container `8080` |
| **security-dashboard** | Read-only observability UI for SOC / compliance demos | Streamlit in container | Host `8501` → container `8501` |
| **sentinel-data** volume | Persistent H2 file database for audit logs | Docker named volume mounted at `/data` | Not published externally |
| **sentinel-net** | Private bridge network for service DNS (`mcp-proxy`, `security-dashboard`) | Docker bridge | Internal only |

### 2.2 Topology diagram

```
                     ┌─────────────────────────────────────┐
                     │           Host / Laptop             │
                     │  :8080                :8501         │
                     └─────┬───────────────────┬───────────┘
                           │                   │
         ┌─────────────────▼───────────────────▼─────────────────┐
         │                   sentinel-net (bridge)               │
         │                                                       │
         │  ┌─────────────────────┐   REST audit    ┌──────────┐ │
         │  │     mcp-proxy       │◄────────────────│dashboard │ │
         │  │  Spring Boot :8080  │  (server-side)  │Streamlit │ │
         │  │                     │                 │  :8501   │ │
         │  │  /v1/mcp/execute    │                 └──────────┘ │
         │  │  /api/audit/*       │                              │
         │  │  /actuator/health   │                              │
         │  └──────────┬──────────┘                              │
         │             │ JDBC                                    │
         │             ▼                                         │
         │      ┌─────────────┐                                  │
         │      │ /data (H2)  │  volume: sentinel-data           │
         │      └─────────────┘                                  │
         └───────────────────────────────────────────────────────┘
```

### 2.3 Trust boundaries

1. **External → proxy:** Untrusted agents and browsers. All execute traffic must present trusted `Host`/`Origin` and a valid Bearer token.
2. **Proxy → audit store:** Trusted internal write path; only the proxy process writes to H2.
3. **Dashboard → proxy:** Trusted service-to-service read path over Docker DNS (`PROXY_BASE_URL=http://mcp-proxy:8080`). The browser never talks to the Docker-internal hostname; operators use `localhost:8501` and `localhost:8080`.
4. **Dashboard → browser:** Streamlit UI with CORS disabled and WebSocket compression disabled for stable reverse-proxy / Docker Desktop connectivity.

---

## 3. Request lifecycle — `POST /v1/mcp/execute`

The following is the authoritative path for an MCP tool-execution payload from wire to audit record.

### Stage A — Ingress & DNS rebinding mitigation (CVE-2026-11624)

**Component:** `DnsRebindingFilter` (highest precedence on `/v1/mcp/execute`)

1. Extract `Host` and `Origin` headers.
2. Normalize and compare against configured allow-lists (`mcp.sentinel.dns-rebinding.allowed-hosts`, `mcp.sentinel.dns-rebinding.allowed-origins`).
3. **Reject** if Host is missing/untrusted, or Origin is missing/untrusted.
4. Persist audit row with reason **`DNS Rebinding Blocked`**, return **HTTP 403** with JSON body `{ status: BLOCKED, message: "DNS Rebinding Blocked", ... }`.
5. If valid, continue the filter chain.

*Rationale:* DNS rebinding attacks trick a browser into treating an attacker-controlled name as a “local” API. Binding policy to explicit Host/Origin allow-lists closes that class of browser-mediated abuse against the execute endpoint.

### Stage B — Agent authentication (OAuth 2.1–style Bearer)

**Component:** `AgentAuthFilter`

1. Require `Authorization: Bearer <token>`.
2. Resolve token via `FgaRegistry` (configuration-backed mock IdP / token registry).
3. **Reject** unknown or missing tokens: audit reason **`Missing or invalid Bearer token`**, **HTTP 401**.
4. On success, bind `AgentIdentity` (agentId + allowed tool set) into `AgentContext` (thread-local + request attribute) for the remainder of the request.

*Rationale:* Identity is established before payload business logic runs. Client-supplied `agent_id` fields are not authoritative.

### Stage C — Deserialization & firewall orchestration

**Component:** `McpProxyController` → `FirewallService.inspect()`

1. Deserialize JSON into `McpExecuteRequest` (`tool_name`, `description`, `arguments`, `metadata`, `prompt`, `session_id`, optional client `agent_id`).
2. **Overwrite** `agent_id` with the authenticated identity from `AgentContext` before serialization for audit.
3. Increment in-flight connection counter (feeds “Active MCP Connections” metric).

### Stage D — Fine-grained authorization (OWASP MCP07 — Excessive Agency)

**Component:** `FirewallService` + `AgentIdentity.mayExecute(toolName)`

1. Compare requested `tool_name` against the token’s allow-list (case-insensitive).
2. **Reject** out-of-scope tools: audit reason **`FGA Scope Violation`**, **HTTP 403**.
3. Example (default registry): `tok_agent_alpha_read` may call `read_file` / `list_dir` but not `search`.

*Rationale:* Prevents a compromised or over-eager agent from exercising capabilities outside its business charter—the core of “excessive agency.”

### Stage E — Dynamic security rule engine (OWASP MCP03 / MCP05)

**Component:** `SecurityRuleEngine.evaluate(toolName, rawPayloadJson)`

Inspection is performed against the **full serialized JSON** (including description and metadata), not only the tool name:

| Check | Outcome reason (representative) |
|-------|---------------------------------|
| Tool in blocked catalog (`bash`, `shell`, `execute_command`, …) | `Unauthorized shell/bash command blocked` |
| Poisoning / jailbreak phrases in description or body | `Tool Poisoning Detected` |
| Path traversal / sensitive paths (`../`, `/etc/passwd`, …) | `Path traversal or sensitive path access blocked` |
| Shell chaining / destructive patterns (`\|`, `&&`, `;`, `rm -rf`) | MCP05-tagged injection reasons |

Any hit → persist **BLOCKED**, return **HTTP 403**.

### Stage F — Allow path & audit persistence

1. Persist **ALLOWED** audit row: timestamp, tool name, authenticated agent ID, session ID, full payload JSON, null reason.
2. Return **HTTP 200** with `{ status: ALLOWED, audit_id, tool_name, message }`.
3. Decrement in-flight counter.

### Stage G — Observability consumption

**Component:** `AuditController` + Streamlit dashboard

- `GET /api/audit/logs` — newest-first audit events  
- `GET /api/audit/metrics` — totals, threats blocked, active connections  

The dashboard classifies rejection reasons into threat classes (DNS Rebinding, Tool Poisoning, FGA Violation, Path Traversal, Command Injection, Auth Failure) for operator triage.

---

## 4. Control mapping summary

| Control objective | Mechanism | Failure mode |
|-------------------|-----------|--------------|
| Prevent DNS rebinding to execute API | Host + Origin allow-list filter | 403 · `DNS Rebinding Blocked` |
| Authenticate agent callers | Bearer token → FGA registry | 401 · `Missing or invalid Bearer token` |
| Limit agent capabilities | Per-token tool scopes | 403 · `FGA Scope Violation` |
| Detect tool schema / prompt poisoning | Payload-wide pattern engine | 403 · `Tool Poisoning Detected` |
| Block command injection & shell tools | Blocked tool set + injection regexes | 403 · shell / MCP05 reasons |
| Block path abuse | Traversal & sensitive-path patterns | 403 · path traversal reason |
| Prove decisions | H2 audit trail + dashboard | Readable via `/api/audit/*` |

---

## 5. Data model & isolation properties

### 5.1 Audit record schema (`audit_logs`)

| Field | Type | Sensitivity | Notes |
|-------|------|-------------|-------|
| `id` | Long (PK) | Low | Monotonic audit identifier returned to caller |
| `timestamp` | Instant | Low | UTC event time |
| `tool_name` | String | Medium | Requested capability |
| `status` | String | Low | `ALLOWED` \| `BLOCKED` |
| `payload` | CLOB | **High** | Full request JSON — may contain paths, prompts, metadata |
| `reason` | String | Medium | Canonical rejection reason or null |
| `agent_id` | String | Medium | Authenticated identity (never trust client spoof) |
| `session_id` | String | Medium | Caller-supplied correlation id |

### 5.2 Isolation properties (MVP)

| Property | Current behavior | Diligence note |
|----------|------------------|----------------|
| **Process isolation** | Proxy and dashboard run in separate containers with distinct UIDs where applied | Lateral movement between UI and PEP requires network compromise on `sentinel-net` |
| **Network isolation** | Audit DB is not exposed on the host; only proxy mounts `/data` | Dashboard cannot open H2 directly—read path is API-only |
| **Identity isolation** | FGA scopes are per-token; agent A cannot authorize agent B’s tools | Tokens are shared secrets in MVP—upgrade path is IdP-issued JWTs |
| **Tenant isolation** | **Single-tenant** deployment model | Multi-tenant SaaS requires DB partitioning / row-level tenant_id (see growth roadmap) |
| **Browser isolation** | Docker DNS names (`mcp-proxy`) are not resolvable from the host browser | Operators must use published localhost ports; prevents accidental leakage of internal URLs into client-side calls |
| **Secret handling** | Demo tokens in config/env; H2 with empty default password suitable for local MVP only | Production must rotate credentials, encrypt at rest, and externalize secrets (Vault / cloud KMS) |
| **Audit integrity** | Append-mostly JPA writes; no delete API exposed | Tamper-evidence (hash chaining, WORM storage) is a post-acquisition hardening item |

### 5.3 Data flow classification

```
Agent payload (confidential) ──write──► mcp-proxy memory ──write──► H2 /data
                                                                      │
Dashboard operator (need-to-know) ◄──read JSON── /api/audit/* ◄───────┘
```

No third-party telemetry is emitted by default. Streamlit usage stats are disabled (`STREAMLIT_BROWSER_GATHER_USAGE_STATS=false`).

---

## 6. Configuration surface

Primary configuration lives in `mcp-proxy/src/main/resources/application.properties`, overridable via environment variables in `docker-compose.yml`:

- `SPRING_DATASOURCE_URL` — H2 file location (`/data/mcp_sentinel` in Compose)
- `MCP_SENTINEL_DNS_REBINDING_ALLOWED_HOSTS` / `_ORIGINS` — CVE-2026-11624 allow-lists
- `mcp.sentinel.fga.<token>.agent-id` / `allowed-tools` — FGA registry entries
- Dashboard: `PROXY_BASE_URL`, Streamlit `--server.enableCORS=false`, `--server.enableWebsocketCompression=false`

---

## 7. Operational characteristics

| Concern | MVP posture |
|---------|-------------|
| Health | Spring Actuator `/actuator/health`; Compose `depends_on: service_healthy` for dashboard |
| Scaling | Vertical / single replica; sticky volume for H2 |
| Backups | Volume snapshot of `sentinel-data` |
| Logging | Structured console logs with ALLOWED/BLOCKED lines; dual persistence in H2 |
| Platform | Multi-arch images (Apple Silicon arm64 + amd64); Temurin JRE Jammy runtime |

---

## 8. Explicit non-goals of the current binary

The following are **intentionally out of scope** for the MVP binary and should not be assumed during diligence:

- Multi-tenant SaaS control plane and billing
- Mutual TLS between agents and proxy
- Streaming MCP transports beyond HTTP POST execute
- Guaranteed sub-millisecond SLOs under multi-region load
- Cryptographic audit chaining / SIEM native connectors

These form the expansion surface documented in [`growth_roadmap.md`](./growth_roadmap.md).

---

## 9. Repository map (implementation anchors)

| Concern | Primary artifacts |
|---------|-------------------|
| DNS rebinding filter | `security/DnsRebindingFilter.java` |
| Bearer auth filter | `security/AgentAuthFilter.java` |
| FGA registry | `security/FgaRegistry.java`, `config/SentinelSecurityProperties.java` |
| Rule engine | `security/SecurityRuleEngine.java` |
| Orchestration | `service/FirewallService.java` |
| Execute API | `controller/McpProxyController.java` |
| Audit API | `controller/AuditController.java` |
| Dashboard | `security-dashboard/app.py` |
| Orchestration | `docker-compose.yml` |

---

*End of architecture specification.*
