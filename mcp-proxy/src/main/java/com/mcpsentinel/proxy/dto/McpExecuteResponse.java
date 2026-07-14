package com.mcpsentinel.proxy.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class McpExecuteResponse {

    private String status;
    private String message;

    @JsonProperty("audit_id")
    private Long auditId;

    @JsonProperty("tool_name")
    private String toolName;

    public McpExecuteResponse() {
    }

    public McpExecuteResponse(String status, String message, Long auditId, String toolName) {
        this.status = status;
        this.message = message;
        this.auditId = auditId;
        this.toolName = toolName;
    }

    public static McpExecuteResponse allowed(Long auditId, String toolName) {
        return new McpExecuteResponse("ALLOWED", "Request passed security policy checks", auditId, toolName);
    }

    public static McpExecuteResponse blocked(Long auditId, String toolName, String reason) {
        return new McpExecuteResponse("BLOCKED", reason, auditId, toolName);
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Long getAuditId() {
        return auditId;
    }

    public void setAuditId(Long auditId) {
        this.auditId = auditId;
    }

    public String getToolName() {
        return toolName;
    }

    public void setToolName(String toolName) {
        this.toolName = toolName;
    }
}
