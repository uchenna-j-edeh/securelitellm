"""Mock classifier for testing — always returns BENIGN without calling any service."""

import os

from router.classifiers.base import BaseClassifier, ClassifierResult

_MOCK_LABEL_ENV = "MOCK_CLASSIFIER_LABEL"


class MockClassifier(BaseClassifier):
    """Stub classifier that returns a fixed label. Intended for CI and unit tests only."""

    def __init__(self) -> None:
        label = os.environ.get(_MOCK_LABEL_ENV, "BENIGN").upper()
        if label not in ("BENIGN", "INJECTION"):
            raise ValueError(f"{_MOCK_LABEL_ENV} must be BENIGN or INJECTION, got {label!r}")
        self._label = label
        self._score = 0.01 if label == "BENIGN" else 0.99

    async def classify(self, text: str) -> ClassifierResult:
        return ClassifierResult(
            label=self._label,
            score=self._score,
            latency_ms=0.0,
            model="mock",
        )
