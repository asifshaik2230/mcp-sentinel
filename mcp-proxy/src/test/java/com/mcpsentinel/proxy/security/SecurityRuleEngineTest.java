package com.mcpsentinel.proxy.security;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityRuleEngineTest {

    @Test
    void allowsSafeToolCall() {
        Optional<String> result = SecurityRuleEngine.evaluate(
                "read_file",
                "{\"tool_name\":\"read_file\",\"arguments\":{\"path\":\"/docs/readme.md\"}}"
        );
        assertFalse(result.isPresent());
    }

    @Test
    void blocksBashTool() {
        Optional<String> result = SecurityRuleEngine.evaluate(
                "bash",
                "{\"tool_name\":\"bash\",\"arguments\":{\"cmd\":\"ls\"}}"
        );
        assertTrue(result.isPresent());
        assertTrue(result.get().contains("RULE 1"));
    }

    @Test
    void blocksShellTool() {
        assertTrue(SecurityRuleEngine.evaluate("shell", "{\"tool_name\":\"shell\"}").isPresent());
    }

    @Test
    void blocksExecuteCommandTool() {
        assertTrue(SecurityRuleEngine.evaluate("execute_command", "{\"tool_name\":\"execute_command\"}").isPresent());
    }

    @Test
    void blocksPipePattern() {
        Optional<String> result = SecurityRuleEngine.evaluate(
                "search",
                "{\"tool_name\":\"search\",\"prompt\":\"cat /etc/passwd | grep root\"}"
        );
        assertTrue(result.isPresent());
        assertTrue(result.get().contains("RULE 2"));
    }

    @Test
    void blocksRmRfPattern() {
        Optional<String> result = SecurityRuleEngine.evaluate(
                "write_file",
                "{\"tool_name\":\"write_file\",\"arguments\":{\"content\":\"rm -rf /tmp/data\"}}"
        );
        assertTrue(result.isPresent());
    }
}
