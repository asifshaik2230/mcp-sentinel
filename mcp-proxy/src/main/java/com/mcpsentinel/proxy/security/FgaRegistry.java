package com.mcpsentinel.proxy.security;

import com.mcpsentinel.proxy.config.SentinelSecurityProperties;
import com.mcpsentinel.proxy.config.SentinelSecurityProperties.AgentGrant;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Mock Fine-Grained Authorization (FGA) registry mapping Bearer tokens to agent scopes.
 * Mimics OAuth 2.1 scoped access tokens for MCP agent identities (OWASP MCP07).
 */
@Component
public class FgaRegistry {

    private static final Logger log = LoggerFactory.getLogger(FgaRegistry.class);

    private final SentinelSecurityProperties properties;
    private final Map<String, AgentIdentity> byToken = new HashMap<>();

    public FgaRegistry(SentinelSecurityProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void load() {
        byToken.clear();
        Map<String, AgentGrant> configured = properties.getFga();
        if (configured == null || configured.isEmpty()) {
            loadDefaults();
        } else {
            configured.forEach((token, grant) -> {
                if (token == null || token.isBlank() || grant == null || grant.getAgentId() == null) {
                    return;
                }
                Set<String> tools = new HashSet<>();
                if (grant.getAllowedTools() != null) {
                    grant.getAllowedTools().forEach(t -> tools.add(t.toLowerCase(Locale.ROOT)));
                }
                byToken.put(token.trim(), new AgentIdentity(token.trim(), grant.getAgentId(), tools));
            });
        }
        log.info("FGA registry loaded with {} agent identities", byToken.size());
    }

    private void loadDefaults() {
        // agent-alpha: read-only file tools
        byToken.put("tok_agent_alpha_read", new AgentIdentity(
                "tok_agent_alpha_read",
                "agent-alpha",
                Set.of("read_file", "list_dir")
        ));
        // agent-beta: search only
        byToken.put("tok_agent_beta_search", new AgentIdentity(
                "tok_agent_beta_search",
                "agent-beta",
                Set.of("search")
        ));
        // agent-gamma: write_file (still subject to content rules)
        byToken.put("tok_agent_gamma_write", new AgentIdentity(
                "tok_agent_gamma_write",
                "agent-gamma",
                Set.of("write_file")
        ));
    }

    public Optional<AgentIdentity> resolve(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byToken.get(bearerToken.trim()));
    }
}
