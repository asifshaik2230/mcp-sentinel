package com.mcpsentinel.proxy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

/**
 * Incoming MCP tool-call payload intercepted by the firewall.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class McpExecuteRequest {

    @NotBlank(message = "tool_name is required")
    @JsonProperty("tool_name")
    private String toolName;

    @JsonProperty("arguments")
    private Map<String, Object> arguments;

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

    public Map<String, Object> getArguments() {
        return arguments;
    }

    public void setArguments(Map<String, Object> arguments) {
        this.arguments = arguments;
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
