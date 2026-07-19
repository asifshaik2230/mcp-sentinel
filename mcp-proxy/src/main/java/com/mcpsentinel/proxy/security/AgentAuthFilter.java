package com.mcpsentinel.proxy.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpsentinel.proxy.dto.McpExecuteResponse;
import com.mcpsentinel.proxy.service.FirewallService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * OAuth 2.1-style Bearer token authentication for MCP execute requests (OWASP MCP07).
 * Resolves agent identity from the FGA registry; scope enforcement happens in FirewallService.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class AgentAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AgentAuthFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final FgaRegistry fgaRegistry;
    private final FirewallService firewallService;
    private final ObjectMapper objectMapper;

    public AgentAuthFilter(
            FgaRegistry fgaRegistry,
            FirewallService firewallService,
            ObjectMapper objectMapper
    ) {
        this.fgaRegistry = fgaRegistry;
        this.firewallService = firewallService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path == null || !path.startsWith("/v1/mcp/execute");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String authorization = request.getHeader("Authorization");
            if (authorization == null || !authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                rejectUnauthorized(response, "Authorization Bearer token required");
                return;
            }

            String token = authorization.substring(BEARER_PREFIX.length()).trim();
            Optional<AgentIdentity> identity = fgaRegistry.resolve(token);
            if (identity.isEmpty()) {
                rejectUnauthorized(response, "Unknown or revoked agent token");
                return;
            }

            AgentIdentity agent = identity.get();
            AgentContext.set(agent);
            request.setAttribute(AgentContext.REQUEST_ATTR, agent);
            log.debug("Authenticated agent_id={} scopes={}", agent.agentId(), agent.scopes());
            filterChain.doFilter(request, response);
        } finally {
            AgentContext.clear();
        }
    }

    private void rejectUnauthorized(HttpServletResponse response, String detail) throws IOException {
        log.warn("{} — {}", RejectionReason.UNAUTHORIZED, detail);
        Long auditId = firewallService.recordExternalBlock(
                "unknown",
                RejectionReason.UNAUTHORIZED,
                "{\"event\":\"auth_failure\",\"detail\":\"" + detail.replace("\"", "'") + "\"}",
                null,
                null
        );
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        McpExecuteResponse body = McpExecuteResponse.blocked(
                auditId,
                "unknown",
                RejectionReason.UNAUTHORIZED
        );
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
