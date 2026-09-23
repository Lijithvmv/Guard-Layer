"""Optional REST API — run GuardLayer as a sidecar service (install the `api` extra).

    uvicorn guardlayer.api:app --host 0.0.0.0 --port 8000
    # or: guardlayer serve

Environment:
    GUARDLAYER_CONFIG   path to a TOML/JSON config (optional)
    GUARDLAYER_API_KEY  if set, every /v1 request must send header `X-API-Key: <value>`
"""

from __future__ import annotations

import hmac
import os
from typing import Any, Literal

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from pydantic import BaseModel, Field
except ModuleNotFoundError as exc:  # pragma: no cover - clearer error than a raw ImportError
    raise ModuleNotFoundError("The REST API needs the 'api' extra. Install it with: pip install 'guardlayer[api]'") from exc

from guardlayer import __version__
from guardlayer.config import build_guard
from guardlayer.pipeline import GuardLayer
from guardlayer.scanners.similarity import SimilarityScanner

MAX_TEXT = 200_000


class InputRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    system_prompt: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class OutputRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    prompt: str | None = None
    system_prompt: str | None = None
    canary_tokens: list[str] = Field(default_factory=list)
    expected_canary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BatchItem(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    direction: Literal["input", "output", "context"] = "input"


class BatchRequest(BaseModel):
    items: list[BatchItem] = Field(max_length=256)


class ToolCallRequest(BaseModel):
    tool: str = Field(max_length=256)
    arguments: dict[str, Any] | str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CanaryAddRequest(BaseModel):
    prompt: str = Field(max_length=MAX_TEXT)
    echo: bool = False


class CanaryCheckRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    token: str | None = None


class CorpusAddRequest(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)


def create_app(guard: GuardLayer | None = None, *, api_key: str | None = None) -> FastAPI:
    engine = guard or build_guard(os.environ.get("GUARDLAYER_CONFIG"))
    key = api_key if api_key is not None else os.environ.get("GUARDLAYER_API_KEY")

    def authorize(x_api_key: str | None = Header(default=None)) -> None:
        if key and not (x_api_key and hmac.compare_digest(x_api_key, key)):
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")

    app = FastAPI(title="GuardLayer", version=__version__, description="Input/output security filtering for LLM and agent applications.")
    app.state.guard = engine
    v1 = [Depends(authorize)]

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/settings", dependencies=v1)
    def settings() -> dict[str, Any]:
        return {
            "version": __version__,
            "flag_threshold": engine.policy.flag_threshold,
            "block_threshold": engine.policy.block_threshold,
            "fail_closed": engine.policy.fail_closed,
            "auto_learn": engine.auto_learn,
            "preset": engine.preset,
            "mode": engine.policy.mode,
            "observe": engine.policy.observe,
            "enforce": engine.policy.enforce,
            "actions": {k: v.value for k, v in engine.policy.actions.items()},
            "scanners": [{"name": s.name, "directions": sorted(s.directions)} for s in engine.scanners],
            "tools": {
                "allowlist": sorted(engine.tool_policy.allowlist) if engine.tool_policy.allowlist is not None else None,
                "denylist": sorted(engine.tool_policy.denylist),
                "egress_allowlist": sorted(engine.tool_policy.egress_allowlist) if engine.tool_policy.egress_allowlist is not None else None,
                "capability_actions": {k: v.value for k, v in engine.tool_policy.capability_actions.items()},
                "rules": [{"name": r.name, "action": r.action.value} for r in engine.tool_policy.rules],  # type: ignore[union-attr]
            },
        }

    @app.post("/v1/scan/input", dependencies=v1)
    def scan_input(req: InputRequest) -> dict[str, Any]:
        return engine.scan_input(req.text, system_prompt=req.system_prompt, metadata=req.metadata).to_dict()

    @app.post("/v1/scan/output", dependencies=v1)
    def scan_output(req: OutputRequest) -> dict[str, Any]:
        return engine.scan_output(
            req.text, prompt=req.prompt, system_prompt=req.system_prompt,
            canary_tokens=req.canary_tokens, expected_canary=req.expected_canary, metadata=req.metadata,
        ).to_dict()  # fmt: skip

    @app.post("/v1/scan/context", dependencies=v1)
    def scan_context(req: ContextRequest) -> dict[str, Any]:
        return engine.scan_context(req.text, source=req.source, metadata=req.metadata).to_dict()

    @app.post("/v1/scan/batch", dependencies=v1)
    def scan_batch(req: BatchRequest) -> dict[str, Any]:
        return {"results": [engine.scan(item.text, item.direction).to_dict() for item in req.items]}

    @app.post("/v1/scan/tool-call", dependencies=v1)
    def scan_tool_call(req: ToolCallRequest) -> dict[str, Any]:
        return engine.scan_tool_call(req.tool, req.arguments, metadata=req.metadata).to_dict()

    @app.post("/v1/canary/add", dependencies=v1)
    def canary_add(req: CanaryAddRequest) -> dict[str, Any]:
        canary = engine.add_canary(req.prompt, echo=req.echo)
        return {"token": canary.token, "prompt": canary.prompt, "echo": canary.echo}

    @app.post("/v1/canary/check", dependencies=v1)
    def canary_check(req: CanaryCheckRequest) -> dict[str, Any]:
        leaked = engine.canaries.find(req.text)
        if req.token and req.token in req.text and req.token not in leaked:
            leaked.append(req.token)
        return {"leaked": bool(leaked), "tokens": leaked}

    @app.post("/v1/corpus/add", dependencies=v1)
    def corpus_add(req: CorpusAddRequest) -> dict[str, Any]:
        scanner = engine.get_scanner("similarity")
        if not isinstance(scanner, SimilarityScanner):
            raise HTTPException(status_code=409, detail="similarity scanner is not enabled")
        added = scanner.store.add(req.texts, {"source": "api", **req.metadata})
        return {"added": added, "size": len(scanner.store)}

    return app


app = create_app()
