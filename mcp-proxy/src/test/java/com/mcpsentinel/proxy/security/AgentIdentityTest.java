package com.mcpsentinel.proxy.security;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentIdentityTest {

    @Test
    void allowsScopedTool() {
        AgentIdentity identity = new AgentIdentity("tok", "agent-alpha", Set.of("read_file", "list_dir"));
        assertTrue(identity.mayExecute("read_file"));
        assertTrue(identity.mayExecute("READ_FILE"));
    }

    @Test
    void deniesOutOfScopeTool() {
        AgentIdentity identity = new AgentIdentity("tok", "agent-alpha", Set.of("read_file"));
        assertFalse(identity.mayExecute("search"));
        assertFalse(identity.mayExecute("bash"));
    }
}
