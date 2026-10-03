"""PromptGuard 2 classifier adapter — uses Groq-hosted meta-llama/llama-prompt-guard-2-86m.

The model returns a float string in the completion content: probability of injection (0–1).
Threshold default: 0.5. Override with PROMPTGUARD_THRESHOLD env var.
"""

import os
import time

import httpx

from router.classifiers.base import BaseClassifier, ClassifierResult

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_MODEL_86M = "meta-llama/llama-prompt-guard-2-86m"
_MODEL_22M = "meta-llama/llama-prompt-guard-2-22m"

DEFAULT_THRESHOLD = 0.5
DEFAULT_TIMEOUT = 10.0


class PromptGuardClassifier(BaseClassifier):
    def __init__(
        self,
        api_key: str | None = None,
        model: str = _MODEL_86M,
        threshold: float | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.model = model
        self.threshold = threshold if threshold is not None else float(
            os.environ.get("PROMPTGUARD_THRESHOLD", DEFAULT_THRESHOLD)
        )
        self.timeout = timeout

        if not self.api_key:
            raise ValueError("GROQ_API_KEY is required for PromptGuardClassifier")

    async def classify(self, text: str) -> ClassifierResult:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                _GROQ_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": text}],
                },
            )
            resp.raise_for_status()

        latency_ms = (time.perf_counter() - t0) * 1000
        data = resp.json()
        raw = data["choices"][0]["message"]["content"].strip()
        score = float(raw)
        label = "INJECTION" if score >= self.threshold else "BENIGN"

        return ClassifierResult(
            label=label,
            score=score,
            latency_ms=latency_ms,
            model=self.model,
        )
