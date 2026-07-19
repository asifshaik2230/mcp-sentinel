package com.mcpsentinel.proxy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

/**
 * Incoming MCP tool-call payload intercepted by the firewall.
 * Inspected fields include schema metadata and description (OWASP MCP03).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class McpExecuteRequest {

    @NotBlank(message = "tool_name is required")
    @JsonProperty("tool_name")
    private String toolName;

    @JsonProperty("description")
    private String description;

    @JsonProperty("arguments")
    private Map<String, Object> arguments;

    @JsonProperty("metadata")
    private Map<String, Object> metadata;

    @JsonProperty("agent_id")
    private String agentId;

    @JsonProperty("session_id")
    private String sessionId;

    @JsonProperty("prompt")
    private String prompt;

    public String getToolName() {
        return toolName;
    }

    public void setToolName(String toolName) {
        this.toolName = toolName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Map<String, Object> getArguments() {
        return arguments;
    }

    public void setArguments(Map<String, Object> arguments) {
        this.arguments = arguments;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getPrompt() {
        return prompt;
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }
}
