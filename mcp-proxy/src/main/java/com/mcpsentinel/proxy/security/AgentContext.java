package com.mcpsentinel.proxy.security;

/**
 * Request-scoped holder for the authenticated agent identity.
 */
public final class AgentContext {

    public static final String REQUEST_ATTR = "mcp.sentinel.agentIdentity";

    private static final ThreadLocal<AgentIdentity> CURRENT = new ThreadLocal<>();

    private AgentContext() {
    }

    public static void set(AgentIdentity identity) {
        CURRENT.set(identity);
    }

    public static AgentIdentity get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
