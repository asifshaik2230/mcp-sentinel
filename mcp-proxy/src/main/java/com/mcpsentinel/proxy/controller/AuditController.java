package com.mcpsentinel.proxy.controller;

import com.mcpsentinel.proxy.dto.AuditMetricsResponse;
import com.mcpsentinel.proxy.entity.AuditLog;
import com.mcpsentinel.proxy.service.FirewallService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST API consumed by the Streamlit security dashboard.
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final FirewallService firewallService;

    public AuditController(FirewallService firewallService) {
        this.firewallService = firewallService;
    }

    @GetMapping("/logs")
    public List<AuditLog> getLogs() {
        return firewallService.getAuditTrail();
    }

    @GetMapping("/metrics")
    public AuditMetricsResponse getMetrics() {
        return firewallService.getMetrics();
    }
}
