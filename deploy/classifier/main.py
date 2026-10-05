"""Local prompt-injection classifier service.

Loads protectai/deberta-v3-base-prompt-injection-v2 from HuggingFace and
serves a simple /classify endpoint so the router can swap classifiers by
changing CLASSIFIER_BACKEND without touching any Python code.

Model is cached in /model_cache (mount a named volume there to persist
across container restarts).

Endpoints:
  POST /classify   {"text": "..."} → {"label": "INJECTION"|"BENIGN", "score": 0.94}
  GET  /health     → {"status": "ok"} once model is loaded, 503 while loading
"""

import os
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

MODEL_ID = os.environ.get("CLASSIFIER_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
CACHE_DIR = os.environ.get("TRANSFORMERS_CACHE", "/model_cache")
MAX_LENGTH = int(os.environ.get("CLASSIFIER_MAX_LENGTH", "512"))

app = FastAPI(title="local-classifier")

_pipe = None
_load_error: str | None = None


@app.on_event("startup")
def load_model() -> None:
    global _pipe, _load_error
    try:
        from transformers import pipeline

        _pipe = pipeline(
            "text-classification",
            model=MODEL_ID,
            device=-1,  # CPU
            model_kwargs={"cache_dir": CACHE_DIR},
        )
        # Warm-up pass so first real call isn't slow
        _pipe("hello", truncation=True, max_length=MAX_LENGTH)
    except Exception as exc:
        _load_error = str(exc)


class ClassifyRequest(BaseModel):
    text: str


@app.post("/classify")
def classify(req: ClassifyRequest) -> JSONResponse:
    if _pipe is None:
        detail = _load_error or "model still loading"
        raise HTTPException(status_code=503, detail=detail)

    t0 = time.perf_counter()
    result = _pipe(req.text, truncation=True, max_length=MAX_LENGTH)[0]
    latency_ms = (time.perf_counter() - t0) * 1000

    raw_label: str = result["label"].upper()
    # Normalise: model returns "INJECTION" or "SAFE" — map to our convention
    label = "INJECTION" if "INJECTION" in raw_label else "BENIGN"

    return JSONResponse(
        {
            "label": label,
            "score": round(float(result["score"]), 6),
            "latency_ms": round(latency_ms, 3),
            "model": MODEL_ID,
        }
    )


@app.get("/health")
def health() -> dict:
    if _pipe is None:
        if _load_error:
            raise HTTPException(status_code=500, detail=_load_error)
        raise HTTPException(status_code=503, detail="model loading")
    return {"status": "ok", "model": MODEL_ID}
