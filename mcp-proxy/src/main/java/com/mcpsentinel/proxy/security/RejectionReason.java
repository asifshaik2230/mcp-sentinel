package com.mcpsentinel.proxy.security;

/**
 * Canonical audit rejection reasons for OWASP MCP Top 10 defenses.
 */
public final class RejectionReason {

    public static final String DNS_REBINDING_BLOCKED = "DNS Rebinding Blocked";
    public static final String TOOL_POISONING_DETECTED = "Tool Poisoning Detected";
    public static final String FGA_SCOPE_VIOLATION = "FGA Scope Violation";
    public static final String UNAUTHORIZED = "Missing or invalid Bearer token";
    public static final String PATH_TRAVERSAL = "Path traversal or sensitive path access blocked";
    public static final String UNAUTHORIZED_SHELL = "Unauthorized shell/bash command blocked";

    private RejectionReason() {
    }
}
