package com.mcpsentinel.proxy.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpsentinel.proxy.config.SentinelSecurityProperties;
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
import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CVE-2026-11624 mitigation: strict Origin + Host validation to defeat DNS rebinding.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class DnsRebindingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DnsRebindingFilter.class);

    private final SentinelSecurityProperties properties;
    private final FirewallService firewallService;
    private final ObjectMapper objectMapper;

    public DnsRebindingFilter(
            SentinelSecurityProperties properties,
            FirewallService firewallService,
            ObjectMapper objectMapper
    ) {
        this.properties = properties;
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
        String host = normalizeHost(request.getHeader("Host"));
        String origin = request.getHeader("Origin");

        Set<String> allowedHosts = properties.getDnsRebinding().getAllowedHosts().stream()
                .map(this::normalizeHost)
                .collect(Collectors.toSet());
        Set<String> allowedOrigins = properties.getDnsRebinding().getAllowedOrigins().stream()
                .map(this::normalizeOrigin)
                .collect(Collectors.toSet());

        if (host == null || host.isBlank() || !allowedHosts.contains(host)) {
            reject(response, "Untrusted or missing Host header: " + host);
            return;
        }

        if (origin == null || origin.isBlank()) {
            reject(response, "Missing Origin header");
            return;
        }

        String normalizedOrigin = normalizeOrigin(origin);
        if (!allowedOrigins.contains(normalizedOrigin)) {
            reject(response, "Untrusted Origin: " + origin);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, String detail) throws IOException {
        log.warn("{} — {}", RejectionReason.DNS_REBINDING_BLOCKED, detail);
        Long auditId = firewallService.recordExternalBlock(
                "unknown",
                RejectionReason.DNS_REBINDING_BLOCKED,
                "{\"event\":\"dns_rebinding\",\"detail\":\"" + escape(detail) + "\"}",
                null,
                null
        );
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        McpExecuteResponse body = McpExecuteResponse.blocked(
                auditId,
                "unknown",
                RejectionReason.DNS_REBINDING_BLOCKED
        );
        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private String normalizeHost(String host) {
        if (host == null) {
            return null;
        }
        return host.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        String trimmed = origin.trim();
        if ("null".equalsIgnoreCase(trimmed)) {
            return "null";
        }
        try {
            URI uri = URI.create(trimmed);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            if (port > 0) {
                return scheme + "://" + host + ":" + port;
            }
            return scheme + "://" + host;
        } catch (Exception e) {
            return trimmed.toLowerCase(Locale.ROOT);
        }
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("\"", "'");
    }
}
