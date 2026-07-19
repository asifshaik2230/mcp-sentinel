package com.mcpsentinel.proxy;

import com.mcpsentinel.proxy.config.SentinelSecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(SentinelSecurityProperties.class)
public class McpProxyApplication {

    public static void main(String[] args) {
        SpringApplication.run(McpProxyApplication.class, args);
    }
}
