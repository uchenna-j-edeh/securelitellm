"""LocalClassifier — calls the self-hosted classifier sidecar over HTTP.

Swap the model by changing CLASSIFIER_MODEL in the sidecar's environment;
no router code changes needed.  The sidecar contract:

  POST /classify  {"text": "..."}
                → {"label": "INJECTION"|"BENIGN", "score": 0.94, ...}
  GET  /health   → 200 once model is loaded, 503 while loading

Any reply outside that contract raises MalformedClassifierResponse, which
safe_classify turns into a fail-closed INJECTION verdict (never cached).
"""

import os
import time

import httpx

from router.classifiers.base import BaseClassifier, ClassifierResult

_DEFAULT_URL = "http://local-classifier:8080"
_DEFAULT_TIMEOUT = 15.0
_VALID_LABELS = ("INJECTION", "BENIGN")


class MalformedClassifierResponse(ValueError):
    """The sidecar returned 200 with a body outside the /classify contract."""


def _parse_response(data: object) -> tuple[str, float]:
    """Validate a /classify body; return (label, score) or raise."""
    if not isinstance(data, dict):
        raise MalformedClassifierResponse(f"expected JSON object, got {type(data).__name__}")
    raw_label = data.get("label")
    if not isinstance(raw_label, str) or raw_label.strip().upper() not in _VALID_LABELS:
        raise MalformedClassifierResponse(f"invalid label: {raw_label!r}")
    score = data.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0.0 <= score <= 1.0:
        raise MalformedClassifierResponse(f"invalid score: {score!r}")
    return raw_label.strip().upper(), float(score)


class LocalClassifier(BaseClassifier):
    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = (base_url or os.environ.get("LOCAL_CLASSIFIER_URL", _DEFAULT_URL)).rstrip(
            "/"
        )
        self.timeout = timeout

    async def classify(self, text: str) -> ClassifierResult:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/classify",
                json={"text": text},
            )
            resp.raise_for_status()
        latency_ms = (time.perf_counter() - t0) * 1000
        try:
            data = resp.json()
        except ValueError as exc:
            raise MalformedClassifierResponse("response body is not JSON") from exc
        label, score = _parse_response(data)

        return ClassifierResult(
            label=label,
            score=score,
            latency_ms=latency_ms,
            model=data["model"] if isinstance(data.get("model"), str) else "local",
        )
