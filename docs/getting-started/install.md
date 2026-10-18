# Install

GuardLayer needs Python 3.10 or later. The core has **no runtime dependencies**.

```bash
pip install "git+https://github.com/Lijithvmv/Guard-Layer"
```

That installs the current `main`, the version the [evaluation](../evaluation.md) measures. `pip install guardlayer`
gives the last release on PyPI (0.8.2), which predates the request ceiling, named sources and the other 0.9 changes.

Optional extras add heavier layers and integrations. Install only what you use: each one brings third-party packages.

| Extra | Adds | Pulls in |
|---|---|---|
| `api` | REST API server | FastAPI, uvicorn, pydantic |
| `signing` | Ed25519-signed audit logs | cryptography |
| `ml` | transformer prompt-injection classifier | transformers, torch (about 750 MB of model weights on first use) |
| `embeddings` | semantic similarity and relevance checks | sentence-transformers |
| `langgraph` | LangGraph / LangChain integration | langgraph |
| `openai-agents` | OpenAI Agents SDK integration | openai-agents |
| `toml` | TOML config on Python 3.10 | tomli |

```bash
pip install "guardlayer[api,signing]"
```

Check the install:

```bash
guardlayer --version
guardlayer scan "Ignore all previous instructions."    # prints BLOCK and exits with code 1
```

## From source

```bash
git clone https://github.com/Lijithvmv/Guard-Layer
cd Guard-Layer
pip install -e ".[dev]"
pytest -q
```

## Docker

The image runs the REST API as a non-root user. See [Deployment](../operations/deployment.md) for hardened Compose and
Kubernetes setups.

```bash
docker build -t guardlayer .
docker run -p 127.0.0.1:8000:8000 -e GUARDLAYER_API_KEY=change-me --read-only --tmpfs /tmp guardlayer
```
