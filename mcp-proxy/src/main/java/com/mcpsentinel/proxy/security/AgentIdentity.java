package com.mcpsentinel.proxy.security;

import java.util.Collections;
import java.util.Locale;
import java.util.Set;

/**
 * Authenticated agent identity resolved from an OAuth 2.1-style Bearer token.
 */
public record AgentIdentity(String token, String agentId, Set<String> allowedTools) {

    public AgentIdentity {
        allowedTools = allowedTools == null
                ? Set.of()
                : Set.copyOf(allowedTools);
    }

    public boolean mayExecute(String toolName) {
        if (toolName == null || toolName.isBlank()) {
            return false;
        }
        String normalized = toolName.trim().toLowerCase(Locale.ROOT);
        return allowedTools.stream()
                .map(t -> t.toLowerCase(Locale.ROOT))
                .anyMatch(normalized::equals);
    }

    public Set<String> scopes() {
        return Collections.unmodifiableSet(allowedTools);
    }
}
