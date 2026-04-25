# Trivy MCP

Trivy MCP is optional. It is a separate Trivy plugin, installed with:

```bash
trivy plugin install mcp
```

Then it can be started with:

```bash
trivy mcp
```

Use MCP only when the user explicitly wants an MCP server or IDE integration. For local security scanning through an AI agent, prefer direct Trivy CLI commands because they are transparent, scriptable, and do not require a running MCP server.

The MCP plugin can scan filesystems, container images, and remote repositories through MCP-enabled clients, and Aqua Platform integration is optional. Do not require or assume an Aqua subscription.
