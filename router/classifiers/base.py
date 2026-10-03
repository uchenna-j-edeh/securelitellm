"""Common classifier interface for all prompt-injection scanners."""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ClassifierResult:
    label: str        # "INJECTION" or "BENIGN"
    score: float      # 0-1; probability of injection
    latency_ms: float
    model: str        # identifier of the classifier that produced this
    cached: bool = False


class BaseClassifier(ABC):
    """Async, fail-open classifier adapter."""

    @abstractmethod
    async def classify(self, text: str) -> ClassifierResult: ...

    async def safe_classify(self, text: str) -> ClassifierResult | None:
        """Classify and return None on any error (fail-open)."""
        t0 = time.perf_counter()
        try:
            return await self.classify(text)
        except Exception:
            return None

    def to_verdict(self, result: ClassifierResult | None) -> dict:
        if result is None:
            return {"label": "UNKNOWN", "score": None, "model": "error", "cached": False}
        return {
            "label": result.label,
            "score": round(result.score, 6),
            "model": result.model,
            "cached": result.cached,
            "latency_ms": round(result.latency_ms, 3),
        }
