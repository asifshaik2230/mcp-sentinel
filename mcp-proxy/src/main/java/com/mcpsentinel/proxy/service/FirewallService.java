package com.mcpsentinel.proxy.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpsentinel.proxy.dto.AuditMetricsResponse;
import com.mcpsentinel.proxy.dto.McpExecuteRequest;
import com.mcpsentinel.proxy.dto.McpExecuteResponse;
import com.mcpsentinel.proxy.entity.AuditLog;
import com.mcpsentinel.proxy.repository.AuditLogRepository;
import com.mcpsentinel.proxy.security.SecurityRuleEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    /** Approximate concurrent in-flight MCP execute calls for the dashboard metric. */
    private final AtomicInteger activeConnections = new AtomicInteger(0);

    public FirewallService(AuditLogRepository auditLogRepository, ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public InspectionResult inspect(McpExecuteRequest request) {
        activeConnections.incrementAndGet();
        try {
            String payloadJson = toJson(request);
            String toolName = request.getToolName() != null ? request.getToolName() : "unknown";

            Optional<String> blockReason = SecurityRuleEngine.evaluate(toolName, payloadJson);

            if (blockReason.isPresent()) {
                AuditLog audit = persist(toolName, "BLOCKED", payloadJson, blockReason.get(), request);
                log.warn("BLOCKED tool_name={} auditId={} reason={}", toolName, audit.getId(), blockReason.get());
                return InspectionResult.blocked(McpExecuteResponse.blocked(audit.getId(), toolName, blockReason.get()));
            }

            AuditLog audit = persist(toolName, "ALLOWED", payloadJson, null, request);
            log.info("ALLOWED tool_name={} auditId={}", toolName, audit.getId());
            return InspectionResult.allowed(McpExecuteResponse.allowed(audit.getId(), toolName));
        } finally {
            activeConnections.decrementAndGet();
        }
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

    private AuditLog persist(String toolName, String status, String payload, String reason, McpExecuteRequest request) {
        AuditLog audit = new AuditLog();
        audit.setTimestamp(Instant.now());
        audit.setToolName(toolName);
        audit.setStatus(status);
        audit.setPayload(payload);
        audit.setReason(reason);
        audit.setAgentId(request.getAgentId());
        audit.setSessionId(request.getSessionId());
        return auditLogRepository.save(audit);
    }

    private String toJson(McpExecuteRequest request) {
        try {
            return objectMapper.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            return String.valueOf(request.getToolName());
        }
    }

    public record InspectionResult(boolean allowed, McpExecuteResponse response) {
        public static InspectionResult allowed(McpExecuteResponse response) {
            return new InspectionResult(true, response);
        }

        public static InspectionResult blocked(McpExecuteResponse response) {
            return new InspectionResult(false, response);
        }
    }
}
