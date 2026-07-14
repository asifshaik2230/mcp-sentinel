package com.mcpsentinel.proxy.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuditMetricsResponse {

    @JsonProperty("total_requests")
    private long totalRequests;

    @JsonProperty("threats_blocked")
    private long threatsBlocked;

    @JsonProperty("allowed_requests")
    private long allowedRequests;

    @JsonProperty("active_mcp_connections")
    private long activeMcpConnections;

    public AuditMetricsResponse() {
    }

    public AuditMetricsResponse(long totalRequests, long threatsBlocked, long allowedRequests, long activeMcpConnections) {
        this.totalRequests = totalRequests;
        this.threatsBlocked = threatsBlocked;
        this.allowedRequests = allowedRequests;
        this.activeMcpConnections = activeMcpConnections;
    }

    public long getTotalRequests() {
        return totalRequests;
    }

    public void setTotalRequests(long totalRequests) {
        this.totalRequests = totalRequests;
    }

    public long getThreatsBlocked() {
        return threatsBlocked;
    }

    public void setThreatsBlocked(long threatsBlocked) {
        this.threatsBlocked = threatsBlocked;
    }

    public long getAllowedRequests() {
        return allowedRequests;
    }

    public void setAllowedRequests(long allowedRequests) {
        this.allowedRequests = allowedRequests;
    }

    public long getActiveMcpConnections() {
        return activeMcpConnections;
    }

    public void setActiveMcpConnections(long activeMcpConnections) {
        this.activeMcpConnections = activeMcpConnections;
    }
}
