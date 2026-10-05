"""LocalClassifier — calls the self-hosted classifier sidecar over HTTP.

Swap the model by changing CLASSIFIER_MODEL in the sidecar's environment;
no router code changes needed.  The sidecar contract:

  POST /classify  {"text": "..."}
                → {"label": "INJECTION"|"BENIGN", "score": 0.94, ...}
  GET  /health   → 200 once model is loaded, 503 while loading
"""

import os
import time

import httpx

from router.classifiers.base import BaseClassifier, ClassifierResult

_DEFAULT_URL = "http://local-classifier:8080"
_DEFAULT_TIMEOUT = 15.0


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
        data = resp.json()

        raw_label: str = data.get("label", "BENIGN").upper()
        label = "INJECTION" if "INJECTION" in raw_label else "BENIGN"

        return ClassifierResult(
            label=label,
            score=float(data.get("score", 0.0)),
            latency_ms=latency_ms,
            model=data.get("model", "local"),
        )
