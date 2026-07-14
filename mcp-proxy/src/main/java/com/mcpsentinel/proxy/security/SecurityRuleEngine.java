package com.mcpsentinel.proxy.security;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Zero-trust rule engine for inspecting MCP tool-call payloads.
 *
 * RULE 1 — Block dangerous tools: bash, shell, execute_command
 * RULE 2 — Block prompt-injection / shell-piping patterns in the payload
 */
public final class SecurityRuleEngine {

    public static final Set<String> BLOCKED_TOOLS = Set.of(
            "bash",
            "shell",
            "execute_command"
    );

    private static final List<ThreatPattern> THREAT_PATTERNS = List.of(
            new ThreatPattern(
                    Pattern.compile("\\|"),
                    "Shell pipe operator '|' detected (RULE 2)"
            ),
            new ThreatPattern(
                    Pattern.compile("&&"),
                    "Shell chaining operator '&&' detected (RULE 2)"
            ),
            new ThreatPattern(
                    Pattern.compile(";"),
                    "Command separator ';' detected (RULE 2)"
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)rm\\s+-rf"),
                    "Destructive 'rm -rf' pattern detected (RULE 2)"
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)ignore\\s+(all\\s+)?(previous|prior)\\s+(instructions|prompts)"),
                    "Prompt-injection jailbreak phrase detected (RULE 2)"
            ),
            new ThreatPattern(
                    Pattern.compile("(?i)(system\\s*:|you\\s+are\\s+now\\s+|DAN\\s+mode)"),
                    "Prompt-injection role-override phrase detected (RULE 2)"
            )
    );

    private SecurityRuleEngine() {
    }

    /**
     * Evaluates the payload against all security rules.
     *
     * @param toolName       MCP tool name
     * @param rawPayloadJson full JSON payload as string (for pattern scanning)
     * @return empty if allowed; otherwise a blocking reason
     */
    public static Optional<String> evaluate(String toolName, String rawPayloadJson) {
        if (toolName == null || toolName.isBlank()) {
            return Optional.of("Missing or empty tool_name");
        }

        String normalized = toolName.trim().toLowerCase();
        if (BLOCKED_TOOLS.contains(normalized)) {
            return Optional.of("Blocked tool_name '" + toolName + "' (RULE 1: dangerous execution tools)");
        }

        String haystack = rawPayloadJson != null ? rawPayloadJson : "";
        for (ThreatPattern threat : THREAT_PATTERNS) {
            if (threat.pattern().matcher(haystack).find()) {
                return Optional.of(threat.reason());
            }
        }

        return Optional.empty();
    }

    private record ThreatPattern(Pattern pattern, String reason) {
    }
}
