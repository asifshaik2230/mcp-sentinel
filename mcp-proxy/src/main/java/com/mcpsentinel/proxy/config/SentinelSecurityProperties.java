package com.mcpsentinel.proxy.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "mcp.sentinel")
public class SentinelSecurityProperties {

    private final DnsRebinding dnsRebinding = new DnsRebinding();
    private final Map<String, AgentGrant> fga = new LinkedHashMap<>();

    public DnsRebinding getDnsRebinding() {
        return dnsRebinding;
    }

    public Map<String, AgentGrant> getFga() {
        return fga;
    }

    public static class DnsRebinding {
        /** Trusted Host header values (hostname or host:port). */
        private List<String> allowedHosts = new ArrayList<>(List.of(
                "localhost",
                "localhost:8080",
                "127.0.0.1",
                "127.0.0.1:8080",
                "mcp-proxy",
                "mcp-proxy:8080"
        ));

        /** Trusted Origin header values (exact match, case-insensitive scheme/host). */
        private List<String> allowedOrigins = new ArrayList<>(List.of(
                "http://localhost:8501",
                "http://127.0.0.1:8501",
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://mcp-proxy:8080",
                "null"
        ));

        public List<String> getAllowedHosts() {
            return allowedHosts;
        }

        public void setAllowedHosts(List<String> allowedHosts) {
            this.allowedHosts = allowedHosts;
        }

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }
    }

    public static class AgentGrant {
        private String agentId;
        private List<String> allowedTools = new ArrayList<>();

        public String getAgentId() {
            return agentId;
        }

        public void setAgentId(String agentId) {
            this.agentId = agentId;
        }

        public List<String> getAllowedTools() {
            return allowedTools;
        }

        public void setAllowedTools(List<String> allowedTools) {
            this.allowedTools = allowedTools;
        }
    }
}
