"""Common classifier interface for all prompt-injection scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ClassifierResult:
    label: str  # "INJECTION" or "BENIGN"
    score: float  # 0-1; probability of injection
    latency_ms: float
    model: str  # identifier of the classifier that produced this
    cached: bool = False


class BaseClassifier(ABC):
    """Async, fail-closed classifier adapter. Classifier is mandatory."""

    @abstractmethod
    async def classify(self, text: str) -> ClassifierResult: ...

    async def safe_classify(self, text: str) -> ClassifierResult:
        """Classify and fail closed on any error — returns INJECTION on exception."""
        try:
            return await self.classify(text)
        except Exception as exc:
            return ClassifierResult(
                label="INJECTION",
                score=1.0,
                latency_ms=0.0,
                model=f"error:{type(exc).__name__}",
            )

    def to_verdict(self, result: ClassifierResult) -> dict:
        if result.model.startswith("error:"):
            return {"label": "INJECTION", "score": 1.0, "model": result.model, "cached": False}
        return {
            "label": result.label,
            "score": round(result.score, 6),
            "model": result.model,
            "cached": result.cached,
            "latency_ms": round(result.latency_ms, 3),
        }
