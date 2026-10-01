# Claude Code

GuardLayer can guard a Claude Code session as a [hook](https://docs.anthropic.com/en/docs/claude-code/hooks): every tool
call is checked before it runs, and what tools return is scanned before Claude reads it.

```bash
guardlayer hook claude-code --print-config          # merge the output into .claude/settings.json
guardlayer --preset strict hook claude-code --print-config   # the same, with a stricter posture
```

| Event | What GuardLayer does |
|---|---|
| `PreToolUse` | Runs the tool policy and session taint. Returns `deny` (Claude sees the reason) or `ask` (you get a permission prompt). Otherwise it returns nothing and Claude Code's own permission rules decide. |
| `PostToolUse` | Scans what `WebFetch`, `Bash`, `Read` and MCP tools returned. If it finds an injection, it marks the session hostile and tells Claude to treat that output as untrusted. |
| `UserPromptSubmit` | Fingerprints secrets you paste, so they can't later leave in a tool call. Blocks prompts only with `--block-prompts`: you are trusted. |

!!! success "It can only tighten"
    The hook **never returns `allow`**, so it can't widen Claude Code's own permission settings, even if it's
    misconfigured or attacked.

Details:

- Claude Code's built-in tools come pre-tagged: `Bash` is exec, `WebFetch` is network, `Edit` is write, `TodoWrite` is
  harmless. For `Write` and `Edit`, only the target path is checked, not the file content, so writing security tests or
  shell scripts doesn't trip the command rules.
- State is kept per Claude Code `session_id` in `~/.guardlayer/sessions` (or `GUARDLAYER_STATE_DIR`), in the file store.
- The hook fails open if something goes wrong, unless `fail_closed` is set (the `strict` preset sets it).

## Faster: the hook server

The command hook starts Python for every event: about 0.6 s on Windows, and Claude Code calls it before *and* after
each tool. The hook server is a long-running GuardLayer that Claude Code calls over HTTP instead, with the same checks:

```bash
guardlayer --config pilot.toml hook claude-code --server --print-config    # merge into .claude/settings.json
```

| Measured on Windows (laptop, best of runs) | Command hook | Hook server |
|---|---|---|
| Before a tool call (`PreToolUse`) | 608 ms | 10 ms (p95 31 ms) |
| After a tool call, 4 KB file read (`PostToolUse`) | about 680 ms | 67 ms (the scan itself) |

How it runs:

- The snippet adds a `SessionStart` command hook (`--ensure-server`) that starts the server in the background if it
  isn't running, and HTTP hooks for the other events. The port is derived from the config and preset, so projects
  with different configs get different servers.
- It listens on 127.0.0.1 only and refuses anything that looks like a browser (an `Origin` header, a non-loopback
  `Host`, a body that isn't JSON), so a web page can't reach it. On a shared machine add `--token-env NAME`: the server
  then requires `Authorization: Bearer $NAME`, and Claude Code sends it from that environment variable.
- Editing the config is picked up on the next event (a broken edit keeps the previous config, with a message in
  `~/.guardlayer/hookserver.log`).

!!! warning "If the server isn't running, tool calls are not checked"
    Claude Code treats a failed connection to an HTTP hook as a non-blocking error and lets the tool call go ahead.
    `--ensure-server` starts the server at the beginning of every session and shows a warning if it can't. If the
    server is stopped *during* a session, calls go unchecked until the next session starts. The command hook has no such
    gap; use it where that matters more than speed.

!!! tip "Repositories that hold attack samples"
    A security tool's own test suite is full of injection strings, and reading it marks the session hostile. For such
    repositories, mark the read tools trusted in a config and pass it with `--config`:

    ```toml
    [tool.Read]
    output = "trusted"

    [tool.Grep]
    output = "trusted"
    ```
