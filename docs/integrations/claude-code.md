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
- State is kept per Claude Code `session_id` in `~/.guardlayer/sessions` (or `GUARDLAYER_STATE_DIR`), in the file store,
  because each hook call is a separate process. Each call takes about 1 s on Windows and less on Linux or macOS.
- The hook fails open if something goes wrong, unless `fail_closed` is set (the `strict` preset sets it).

!!! tip "Repositories that hold attack samples"
    A security tool's own test suite is full of injection strings, and reading it marks the session hostile. For such
    repositories, mark the read tools trusted in a config and pass it with `--config`:

    ```toml
    [session]
    trusted_tools = ["Read", "Grep"]
    ```
