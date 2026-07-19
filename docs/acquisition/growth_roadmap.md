# MCP-Sentinel — Post-Acquisition Growth Roadmap

**Document type:** Strategic product & valuation brief  
**Audience:** Acquiring founders, product leadership, and investment diligence  
**Thesis:** MCP-Sentinel today is a **credible, demoable PEP (policy enforcement point)** for MCP. The valuation multiply comes from turning that PEP into the **default trust fabric** for agentic enterprise workloads—distribution via SDKs, identity via corporate IdP, and data plane scale via managed cloud backends.

---

## 1. Current asset (what the buyer is purchasing)

MCP-Sentinel ships as a containerized zero-trust firewall with:

- Interception proxy for MCP tool execution (`/v1/mcp/execute`)
- Automated mitigations aligned to **OWASP MCP Top 10** (notably MCP03, MCP05, MCP07) and **CVE-2026-11624**
- Bearer-scoped Fine-Grained Authorization with audit-stamped agent identity
- Real-time SOC-style Streamlit dashboard and REST audit APIs
- One-command Docker Compose deployability for POCs and bake-offs

This is sufficient to win **design partnerships, security bake-offs, and early ARR** with AI platform teams. The roadmap below focuses on **low-hanging, high-multiple** expansions that convert a sharp MVP into a durable B2B SaaS franchise.

---

## 2. Valuation framework

| Lever | Why buyers pay | Roadmap theme |
|-------|----------------|---------------|
| **Distribution** | Becomes default in agent frameworks → high attach rate | Native SDKs (LangChain / LlamaIndex / custom MCP clients) |
| **Identity lock-in** | Enterprise procurement requires SSO / SCIM | OIDC / Active Directory agent provisioning |
| **Data gravity** | Audit + embeddings + policy history hard to rip out | Managed vector / warehouse backends |
| **Compliance narrative** | Maps cleanly to insurer / auditor checklists | Continuous control monitoring & attestations |
| **Expansion revenue** | Seat / agent / event-based pricing | Multi-tenant control plane + usage metering |

---

## 3. Priority vector A — Native SDK wrappers (fastest path to design-win volume)

### Opportunity
Security products that require developers to “remember to call the firewall” lose to products that are **one import away**. Wrapping MCP-Sentinel as the default transport or tool callback for mainstream agent frameworks collapses adoption friction and creates viral distribution inside engineering orgs.

### Build
1. **Python SDK (`mcp-sentinel-sdk`)**  
   - Drop-in HTTP client that always injects Bearer token, trusted Origin, and session IDs  
   - Decorators / callbacks for LangChain `Tool` and LlamaIndex `FunctionTool` that route invocations through `/v1/mcp/execute`  
   - Structured exceptions mapping 401/403 reasons to developer-actionable errors  

2. **TypeScript / Node SDK** for MCP clients embedded in Cursor-like IDEs and internal agent runtimes  

3. **Reference adapters**  
   - LangChain: `SentinelToolNode` / tool wrapper  
   - LlamaIndex: query-engine tool shim  
   - OpenAI Agents / custom MCP hosts: middleware hook  

### Commercial impact
- Shortens POC from “wire curl correctly” to `pip install` + three lines of config  
- Positions Sentinel as **infrastructure**, not a sidecar experiment  
- Enables marketplace listings (LangChain Hub, LlamaHub) as unpaid distribution channels  

### Effort / sequencing
**S–M effort, 4–8 weeks** for Python + one framework adapter. Highest ROI first ninety days post-close.

---

## 4. Priority vector B — Corporate identity: Active Directory / OIDC agent provisioning

### Opportunity
The MVP FGA registry (static bearer tokens in config) proves the authorization model but will not pass enterprise security review. Buyers need agents to be **first-class identities**—provisioned, rotated, revoked—under the same IdP that governs humans.

### Build
1. **OIDC / OAuth 2.1 resource-server mode**  
   - Validate JWT access tokens (issuer, audience, signature, expiry)  
   - Map claims (`sub`, `client_id`, custom `mcp_scopes`) → `AgentIdentity`  

2. **Directory-backed agent provisioning**  
   - Azure AD / Entra ID app registrations or workload identities per agent fleet  
   - Okta / Auth0 machine-to-machine applications  
   - Optional SCIM for lifecycle (create/disable agent principals)  

3. **Policy admin UI**  
   - Replace Streamlit-only ops view with a tenant admin console for scope assignment  
   - Break-glass workflows and time-bound elevations with mandatory audit reasons  

### Commercial impact
- Unlocks Fortune 500 procurement (SSO checkbox)  
- Supports **per-agent** or **per-identity** pricing instead of flat instance fees  
- Creates switching costs: scopes and agent inventories live in the customer’s IdP + Sentinel policy store  

### Effort / sequencing
**M effort, 8–12 weeks** with a single IdP (Entra or Okta) as the lighthouse integration.

---

## 5. Priority vector C — High-throughput cloud data plane (audit + intelligence)

### Opportunity
H2 file storage is perfect for local demos and single-tenant appliances. SaaS-scale customers generate millions of tool calls per day; they also want **semantic search over attacks**, anomaly detection, and long-term retention for legal hold. Moving the data plane to managed cloud stores creates both scalability and a second product surface: **Agent Security Analytics**.

### Build
1. **Transactional audit store**  
   - PostgreSQL / Aurora or Cloud Spanner for multi-tenant audit rows with `tenant_id`  
   - Partitioning by time + tenant; lifecycle policies (hot / warm / cold)  

2. **Vector intelligence layer**  
   - Embed blocked payloads and poisoning phrases into a managed vector store (pgvector, Pinecone, OpenSearch k-NN, Vertex Matching Engine)  
   - Similarity search: “show me attacks like this one across my fleet”  
   - Optional model-assisted clustering of novel jailbreak variants to feed rule-pack updates  

3. **Streaming export**  
   - Kafka / Pub/Sub / Event Hubs connectors to customer SIEM (Splunk, Sentinel, Chronicle)  
   - Signed audit batches for compliance warehouses  

### Commercial impact
- Justifies **usage-based pricing** (events ingested, retention months, vector queries)  
- Elevates Sentinel from firewall → **security data product**  
- Improves retention: historical attack corpora become institutional memory  

### Effort / sequencing
**M–L effort**; introduce Postgres in parallel with H2 for appliance mode, then vector features as a paid tier.

---

## 6. Secondary vectors (year-one portfolio)

### 6.1 Managed cloud SaaS & multi-tenancy
Control plane with orgs, projects, API keys, RBAC for human operators, regional deploy (US/EU), and SOC2-ready tenancy isolation. Converts Compose appliance into recurring SaaS ARR.

### 6.2 Policy-as-code & rule packs
Versioned YAML/Rego policies, signed rule packs for verticals (healthcare, finance), and GitOps sync. Sells to platform teams who refuse “regex in a JAR” as their long-term model—while keeping the current engine as a fast path.

### 6.3 Sidecar / service-mesh deployment
Envoy WASM or Kubernetes validating admission patterns for MCP gateways already inside the mesh. Expands TAM beyond “teams willing to change agent base URL.”

### 6.4 Continuous attestation & insurer packaging
Scheduled PDF/JSON control reports mapping blocked events to OWASP MCP categories—marketable to cyber insurers and GRC platforms as automated evidence.

### 6.5 Marketplace & OEM
White-label the proxy for LLM gateway vendors; revenue share on protected agent seats.

---

## 7. Suggested 12-month execution plan (post-close)

| Quarter | Focus | Exit criteria |
|---------|-------|---------------|
| **Q1** | Python SDK + LangChain adapter; Postgres audit dual-write; one OIDC pilot | 3 design partners routing production-like traffic; SSO demo in sales cycle |
| **Q2** | Entra/Okta GA; multi-tenant control plane alpha; SIEM export | First paid SaaS logos; usage metering live |
| **Q3** | Vector analytics tier; policy-as-code v1; EU region | Attach rate of analytics >30% on new ARR |
| **Q4** | Mesh/sidecar option; insurer/GRC pack; OEM discussions | Clear category narrative: “Zero-Trust for MCP” with measurable NRR |

---

## 8. Pricing architecture (illustrative for buyers)

| Tier | Includes | Monetization |
|------|----------|--------------|
| **Appliance / Edge** | Compose / K8s self-host, core rule engine, local audit | Annual license per cluster |
| **Cloud Standard** | Multi-tenant SaaS, OIDC, 90-day retention | Per agent identity / month + event overage |
| **Cloud Enterprise** | Vector analytics, SIEM export, policy-as-code, dedicated region | Commit ARR + premium support |

The existing demo tokens and dashboard make **time-to-first-wow** under five minutes—critical for Acquire.com-style buyer demos and post-acquisition sales motion.

---

## 9. Competitive moat trajectory

1. **Today:** Correctness of controls + clarity of audit reasons + instant Docker demo.  
2. **+SDKs:** Default instrumentation in agent codebases.  
3. **+IdP:** Enterprise procurement lock-in.  
4. **+Data plane:** Historical attack intelligence and analytics attach.  
5. **Outcome:** Category-defining “Zero-Trust control plane for MCP,” difficult to displace without rewriting customer agent fleets and identity mappings.

---

## 10. Diligence-ready risks & mitigations

| Risk | Mitigation on roadmap |
|------|------------------------|
| Static demo tokens insufficient for production | Vector B (OIDC / AD) |
| Single-tenant H2 limits SaaS claims | Vector C (Postgres + tenancy) |
| Developer friction slows adoption | Vector A (SDKs) |
| Rule evasion / novel jailbreaks | Vector analytics + signed rule-pack updates |
| Category competition from API gateways | Specialize ruthlessly on MCP semantics + OWASP mapping |

---

## 11. Closing recommendation for the acquirer

Treat the current repository as **Day-0 product truth**: a working firewall with differentiated OWASP MCP narrative and a polished observability story. Invest immediately in **SDK distribution** and **corporate identity**—the two moves that convert technical admiration into enterprise contracts—then scale the **audit/intelligence data plane** to expand net revenue retention.

MCP-Sentinel does not need to become a general API gateway. It needs to become the **mandatory compliance layer every serious autonomous agent crosses**—and this roadmap is the shortest path from that thesis to a premium SaaS multiple.

---

*End of growth roadmap.*
