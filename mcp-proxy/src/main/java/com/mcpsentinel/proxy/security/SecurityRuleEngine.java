package com.mcpsentinel.proxy.security;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Zero-trust rule engine for inspecting MCP tool-call payloads.
 *
 * <ul>
 *   <li>OWASP MCP03 / MCP05 — Tool poisoning &amp; command injection</li>
 *   <li>Blocks unauthorized shell tools and path traversal</li>
 * </ul>
 */
public final class SecurityRuleEngine {

    public static final Set<String> BLOCKED_TOOLS = Set.of(
            "bash",
            "shell",
            "execute_command",
            "exec",
            "run_terminal",
            "terminal"
    );

    private static final List<ThreatPattern> POISONING_PATTERNS = List.of(
            new ThreatPattern(
                    Pattern.compile("(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|prompts?|rules?)"),
                    RejectionReason.TOOL_POISONING_DETECTED
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)system\\s+override"),
                    RejectionReason.TOOL_POISONING_DETECTED
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)(you\\s+are\\s+now\\s+|DAN\\s+mode|jailbreak)"),
                    RejectionReason.TOOL_POISONING_DETECTED
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)disregard\\s+(your\\s+)?(safety|system)\\s+(guidelines?|prompt)"),
                    RejectionReason.TOOL_POISONING_DETECTED
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)<\\s*/?\\s*system\\s*>"),
                    RejectionReason.TOOL_POISONING_DETECTED
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)hidden\\s+instruction"),
                    RejectionReason.TOOL_POISONING_DETECTED
            )
    );

    private static final List<ThreatPattern> INJECTION_PATTERNS = List.of(
            new ThreatPattern(
                    Pattern.compile("\\|"),
                    "Shell pipe operator '|' detected (MCP05)"
            ),
            new ThreatPattern(
                    Pattern.compile("&&"),
                    "Shell chaining operator '&&' detected (MCP05)"
            ),
            new ThreatPattern(
                    Pattern.compile(";"),
                    "Command separator ';' detected (MCP05)"
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)rm\\s+-rf"),
                    "Destructive 'rm -rf' pattern detected (MCP05)"
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)\\b(bash|sh|zsh|cmd\\.exe|powershell)\\b.*(-c|/c)\\b"),
                    RejectionReason.UNAUTHORIZED_SHELL
            )
    );

    private static final List<ThreatPattern> PATH_TRAVERSAL_PATTERNS = List.of(
            new ThreatPattern(
                    Pattern.compile("(?i)/etc/passwd"),
                    RejectionReason.PATH_TRAVERSAL
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)/etc/shadow"),
                    RejectionReason.PATH_TRAVERSAL
            ),
            new ThreatPattern(
                    Pattern.compile("\\.\\./"),
                    RejectionReason.PATH_TRAVERSAL
            ),
            new ThreatPattern(
                    Pattern.compile("\\.\\.\\\\"),
                    RejectionReason.PATH_TRAVERSAL
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)%2e%2e(%2f|/)"),
                    RejectionReason.PATH_TRAVERSAL
            )
    );

    private SecurityRuleEngine() {
    }

    /**
     * Evaluates tool name + full JSON payload (schema, metadata, descriptions, arguments).
     *
     * @return empty if allowed; otherwise a blocking reason suitable for audit logging
     */
    public static Optional<String> evaluate(String toolName, String rawPayloadJson) {
        if (toolName == null || toolName.isBlank()) {
            return Optional.of("Missing or empty tool_name");
        }

        String normalized = toolName.trim().toLowerCase(Locale.ROOT);
        if (BLOCKED_TOOLS.contains(normalized)) {
            return Optional.of(RejectionReason.UNAUTHORIZED_SHELL);
        }

        String haystack = rawPayloadJson != null ? rawPayloadJson : "";

        for (ThreatPattern threat : POISONING_PATTERNS) {
            if (threat.pattern().matcher(haystack).find()) {
                return Optional.of(threat.reason());
            }
        }

        for (ThreatPattern threat : PATH_TRAVERSAL_PATTERNS) {
            if (threat.pattern().matcher(haystack).find()) {
                return Optional.of(threat.reason());
            }
        }

        for (ThreatPattern threat : INJECTION_PATTERNS) {
            if (threat.pattern().matcher(haystack).find()) {
                return Optional.of(threat.reason());
            }
        }

        return Optional.empty();
    }

    private record ThreatPattern(Pattern pattern, String reason) {
    }
}
