"""Local prompt-injection classifier service.

Loads protectai/deberta-v3-base-prompt-injection-v2 from HuggingFace and
serves a simple /classify endpoint so the router can swap classifiers by
changing CLASSIFIER_BACKEND without touching any Python code.

Model is cached in /model_cache (mount a named volume there to persist
across container restarts).

Long texts: the model reads at most CLASSIFIER_MAX_LENGTH tokens (512), so a
longer text is split into overlapping windows of that size
(CLASSIFIER_WINDOW_OVERLAP tokens shared between neighbours, default 256) and
every window is classified in one batch. The text is INJECTION if any window
is; the score is that window's. Overlap means an injection shorter than the
overlap is whole in at least one window, even where windows meet.

Endpoints:
  POST /classify   {"text": "..."} → {"label": "INJECTION"|"BENIGN", "score": 0.94,
                                      "windows": 1, ...}
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
WINDOW_OVERLAP = int(os.environ.get("CLASSIFIER_WINDOW_OVERLAP", "256"))

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


def window_spans(n_tokens: int, size: int, overlap: int) -> list[tuple[int, int]]:
    """[start, end) token spans of *size* that cover n_tokens, sharing *overlap*."""
    if not 0 <= overlap < size:
        raise ValueError("overlap must be at least 0 and smaller than the window size")
    if n_tokens <= size:
        return [(0, n_tokens)]
    step = size - overlap
    spans = []
    start = 0
    while True:
        end = min(start + size, n_tokens)
        spans.append((start, end))
        if end == n_tokens:
            return spans
        start += step


def split_windows(text: str, tokenizer, size: int, overlap: int) -> list[str]:
    """The text cut into overlapping windows the model can read whole."""
    # The model adds special tokens ([CLS], [SEP]) to each input.
    body = size - tokenizer.num_special_tokens_to_add(pair=False)
    enc = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
    offsets = enc["offset_mapping"]
    if len(offsets) <= body:
        return [text]
    return [
        text[offsets[start][0] : offsets[end - 1][1]]
        for start, end in window_spans(len(offsets), body, overlap)
    ]


def combine(results: list[dict]) -> tuple[str, float]:
    """INJECTION if any window is, with the highest such score; else the least sure BENIGN."""
    flagged = [r for r in results if "INJECTION" in r["label"].upper()]
    if flagged:
        return "INJECTION", max(float(r["score"]) for r in flagged)
    return "BENIGN", min(float(r["score"]) for r in results)


@app.post("/classify")
def classify(req: ClassifyRequest) -> JSONResponse:
    if _pipe is None:
        detail = _load_error or "model still loading"
        raise HTTPException(status_code=503, detail=detail)

    t0 = time.perf_counter()
    windows = split_windows(req.text, _pipe.tokenizer, MAX_LENGTH, WINDOW_OVERLAP)
    results = _pipe(windows, truncation=True, max_length=MAX_LENGTH)
    # Normalise: model returns "INJECTION" or "SAFE" — map to our convention
    label, score = combine(results)
    latency_ms = (time.perf_counter() - t0) * 1000

    return JSONResponse(
        {
            "label": label,
            "score": round(score, 6),
            "windows": len(windows),
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
