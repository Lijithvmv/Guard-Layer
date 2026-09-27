# REST API

For non-Python services, or one guard shared by many apps. `pip install "guardlayer[api]"`, then:

```bash
GUARDLAYER_API_KEY=change-me guardlayer serve --host 127.0.0.1 --port 8000
# or: docker run -p 127.0.0.1:8000:8000 -e GUARDLAYER_API_KEY=change-me guardlayer
```

| Method | Path | Body |
|---|---|---|
| GET | `/health` | none |
| GET | `/v1/settings` | none |
| POST | `/v1/scan/input` | `{text, system_prompt?, metadata?, session_id?}` |
| POST | `/v1/scan/output` | `{text, prompt?, system_prompt?, canary_tokens?, expected_canary?, metadata?, session_id?}` |
| POST | `/v1/scan/context` | `{text, source?, metadata?, session_id?}` |
| POST | `/v1/scan/batch` | `{items: [{text, direction}]}` |
| POST | `/v1/scan/tool-call` | `{tool, arguments, metadata?, session_id?}` (verdict may be `review`) |
| POST | `/v1/scan/tool-result` | `{tool, result, metadata?, session_id?}` |
| GET · DELETE | `/v1/sessions/{id}` | session taint summary · reset |
| POST | `/v1/canary/add` · `/v1/canary/check` | `{prompt, echo?}` · `{text}` |
| POST | `/v1/corpus/add` | `{texts: [...]}` |

Every `/v1` route requires the `X-API-Key` header when `GUARDLAYER_API_KEY` is set (compared in constant time).
Interactive docs are served at `/docs`.

```bash
curl -s localhost:8000/v1/scan/tool-call -H "X-API-Key: change-me" -H "Content-Type: application/json" \
  -d '{"tool": "bash", "arguments": {"cmd": "rm -rf ~"}}'
```

!!! warning
    Never expose the API to the internet. Run it as a sidecar on loopback or as an internal service behind TLS; see
    [Deployment](../operations/deployment.md).
