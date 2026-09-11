"""Optional REST API (install the `api` extra: `pip install guardlayer[api]`).

Run with:  uvicorn guardlayer.api:app --reload
POST /scan  {"text": "...", "direction": "input"}  ->  ScanResult
"""

from __future__ import annotations

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
except ModuleNotFoundError as exc:  # pragma: no cover - clearer error than a raw ImportError
    raise ModuleNotFoundError(
        "The REST API needs the 'api' extra. Install it with: pip install 'guardlayer[api]'"
    ) from exc

from guardlayer import GuardLayer, __version__
from guardlayer.models import Direction

app = FastAPI(title="GuardLayer", version=__version__)
_engine = GuardLayer()


class ScanRequest(BaseModel):
    text: str
    direction: Direction = "input"


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    return _engine.scan(req.text, direction=req.direction).to_dict()
