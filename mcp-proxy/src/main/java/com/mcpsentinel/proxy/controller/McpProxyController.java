package com.mcpsentinel.proxy.controller;

import com.mcpsentinel.proxy.dto.McpExecuteRequest;
import com.mcpsentinel.proxy.dto.McpExecuteResponse;
import com.mcpsentinel.proxy.service.FirewallService;
import com.mcpsentinel.proxy.service.FirewallService.InspectionResult;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Firewall intercept point for MCP tool execution requests.
 */
@RestController
@RequestMapping("/v1/mcp")
public class McpProxyController {

    private final FirewallService firewallService;

    public McpProxyController(FirewallService firewallService) {
        this.firewallService = firewallService;
    }

    @PostMapping("/execute")
    public ResponseEntity<McpExecuteResponse> execute(@Valid @RequestBody McpExecuteRequest request) {
        InspectionResult result = firewallService.inspect(request);
        if (!result.allowed()) {
            return ResponseEntity.status(result.status()).body(result.response());
        }
        return ResponseEntity.ok(result.response());
    }
}
