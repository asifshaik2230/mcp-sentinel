package com.mcpsentinel.proxy.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpsentinel.proxy.dto.AuditMetricsResponse;
import com.mcpsentinel.proxy.dto.McpExecuteRequest;
import com.mcpsentinel.proxy.dto.McpExecuteResponse;
import com.mcpsentinel.proxy.entity.AuditLog;
import com.mcpsentinel.proxy.repository.AuditLogRepository;
import com.mcpsentinel.proxy.security.AgentContext;
import com.mcpsentinel.proxy.security.AgentIdentity;
import com.mcpsentinel.proxy.security.RejectionReason;
import com.mcpsentinel.proxy.security.SecurityRuleEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class FirewallService {

    private static final Logger log = LoggerFactory.getLogger(FirewallService.class);

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;
    private final AtomicInteger activeConnections = new AtomicInteger(0);

    public FirewallService(AuditLogRepository auditLogRepository, ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public InspectionResult inspect(McpExecuteRequest request) {
        activeConnections.incrementAndGet();
        try {
            AgentIdentity identity = AgentContext.get();
            String toolName = request.getToolName() != null ? request.getToolName() : "unknown";

            // Prefer authenticated agent identity over client-supplied agent_id
            if (identity != null) {
                request.setAgentId(identity.agentId());
            }

            String payloadJson = toJson(request);
            String agentId = request.getAgentId();

            if (identity == null) {
                AuditLog audit = persist(toolName, "BLOCKED", payloadJson, RejectionReason.UNAUTHORIZED, agentId, request.getSessionId());
                log.warn("BLOCKED tool_name={} auditId={} reason={}", toolName, audit.getId(), RejectionReason.UNAUTHORIZED);
                return InspectionResult.blocked(
                        HttpStatus.UNAUTHORIZED,
                        McpExecuteResponse.blocked(audit.getId(), toolName, RejectionReason.UNAUTHORIZED)
                );
            }

            // OWASP MCP07 — Fine-grained authorization (scoped tools)
            if (!identity.mayExecute(toolName)) {
                AuditLog audit = persist(
                        toolName,
                        "BLOCKED",
                        payloadJson,
                        RejectionReason.FGA_SCOPE_VIOLATION,
                        identity.agentId(),
                        request.getSessionId()
                );
                log.warn("BLOCKED tool_name={} agent={} auditId={} reason={}",
                        toolName, identity.agentId(), audit.getId(), RejectionReason.FGA_SCOPE_VIOLATION);
                return InspectionResult.blocked(
                        HttpStatus.FORBIDDEN,
                        McpExecuteResponse.blocked(audit.getId(), toolName, RejectionReason.FGA_SCOPE_VIOLATION)
                );
            }

            Optional<String> blockReason = SecurityRuleEngine.evaluate(toolName, payloadJson);
            if (blockReason.isPresent()) {
                AuditLog audit = persist(
                        toolName,
                        "BLOCKED",
                        payloadJson,
                        blockReason.get(),
                        identity.agentId(),
                        request.getSessionId()
                );
                log.warn("BLOCKED tool_name={} agent={} auditId={} reason={}",
                        toolName, identity.agentId(), audit.getId(), blockReason.get());
                return InspectionResult.blocked(
                        HttpStatus.FORBIDDEN,
                        McpExecuteResponse.blocked(audit.getId(), toolName, blockReason.get())
                );
            }

            AuditLog audit = persist(toolName, "ALLOWED", payloadJson, null, identity.agentId(), request.getSessionId());
            log.info("ALLOWED tool_name={} agent={} auditId={}", toolName, identity.agentId(), audit.getId());
            return InspectionResult.allowed(McpExecuteResponse.allowed(audit.getId(), toolName));
        } finally {
            activeConnections.decrementAndGet();
        }
    }

    /**
     * Persist a block raised by servlet filters (DNS rebinding / auth) before the controller runs.
     */
    @Transactional
    public Long recordExternalBlock(
            String toolName,
            String reason,
            String payloadJson,
            String agentId,
            String sessionId
    ) {
        AuditLog audit = persist(
                toolName != null ? toolName : "unknown",
                "BLOCKED",
                payloadJson != null ? payloadJson : "{}",
                reason,
                agentId,
                sessionId
        );
        return audit.getId();
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getAuditTrail() {
        return auditLogRepository.findAllByOrderByTimestampDesc();
    }

    @Transactional(readOnly = true)
    public AuditMetricsResponse getMetrics() {
        long total = auditLogRepository.count();
        long blocked = auditLogRepository.countByStatus("BLOCKED");
        long allowed = auditLogRepository.countByStatus("ALLOWED");
        long sessions = auditLogRepository.countDistinctSessions();
        long active = Math.max(activeConnections.get(), 0);
        long activeMetric = active > 0 ? active : sessions;
        return new AuditMetricsResponse(total, blocked, allowed, activeMetric);
    }

    public int getActiveConnections() {
        return activeConnections.get();
    }

    private AuditLog persist(
            String toolName,
            String status,
            String payload,
            String reason,
            String agentId,
            String sessionId
    ) {
        AuditLog audit = new AuditLog();
        audit.setTimestamp(Instant.now());
        audit.setToolName(toolName);
        audit.setStatus(status);
        audit.setPayload(payload);
        audit.setReason(reason);
        audit.setAgentId(agentId);
        audit.setSessionId(sessionId);
        return auditLogRepository.save(audit);
    }

    private String toJson(McpExecuteRequest request) {
        try {
            return objectMapper.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            return String.valueOf(request.getToolName());
        }
    }

    public record InspectionResult(boolean allowed, HttpStatus status, McpExecuteResponse response) {
        public static InspectionResult allowed(McpExecuteResponse response) {
            return new InspectionResult(true, HttpStatus.OK, response);
        }

        public static InspectionResult blocked(HttpStatus status, McpExecuteResponse response) {
            return new InspectionResult(false, status, response);
        }
    }
}
