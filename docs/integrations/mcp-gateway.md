# MCP gateway

Any agent that uses MCP servers can run behind GuardLayer without code changes: point the agent at the gateway instead
of the server, and the gateway starts (stdio) or connects to (HTTP) the real server and relays every message.

On the way through it:

- **checks every tool call** before it reaches the server. A refused call gets a tool error back that says why, and
  the server never sees it. A call that needs a person's approval is **asked about through the client** (MCP
  elicitation: the person sees what the call does and why it was held, and approves or declines); a client that can't
  ask gets a refusal. `--on-review deny` always refuses; `--on-review allow` lets reviews through, logged;
- **scans every result** before the agent reads it, so the session knows what the agent has read; a likely injection is
  flagged in the result (or replaced, with `--withhold`);
- **scans every tool description** the server advertises; a tool whose description carries an injection (a poisoned
  server) is removed from the list.

Tools are judged as `mcp__<name>__<tool>`, as Claude Code names them, so `[tool.NAME]` declarations, `policy draft`,
`policy check` and `default_task` allow-lists work the same way. MCP tools are remote (their output is untrusted) unless
you declare otherwise.

## stdio (a local server)

In the agent's MCP configuration, replace the server's command with the gateway, and put the server's command after `--`:

```json
{
  "mcpServers": {
    "github": {
      "command": "guardlayer",
      "args": ["--config", "guardlayer.toml", "mcp-gateway", "--name", "github", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

## Streamable HTTP (a remote server)

```bash
guardlayer --config guardlayer.toml mcp-gateway --name docs --listen 127.0.0.1:8766 --upstream-url https://example.com/mcp
```

and point the agent at `http://127.0.0.1:8766/mcp`. Each MCP session (`Mcp-Session-Id`) gets its own GuardLayer session.
The gateway doesn't offer the optional server-to-client GET stream.

## What it can't see

The gateway sees tool traffic, not the conversation: it can't scan the user's own messages (use the SDK or a hook for
that). Approval needs a client with the elicitation capability; over HTTP the question travels on the call's event
stream, so the client must accept `text/event-stream`. An unanswered question is declined after 10 minutes.

## Measured

Invaris AgentSec's suite delivered over MCP (its attack host as the server, its rule-based vulnerable agent as the
client; 35 scenarios): 35 with findings when the agent connects directly, 30 through the gateway with no configuration,
19 with the two allowed tools declared as a `default_task`. The categories left are ones GuardLayer doesn't cover (loops
and budgets, restricted documents echoed in answers, a system-prompt secret not registered as a canary).
