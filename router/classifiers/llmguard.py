"""LLM Guard adapter — optional local classifier using the llm-guard package.

Install: pip install llm-guard
If the package is not installed, instantiation raises ImportError.

Uses PromptInjection scanner. Score is 1.0 when injection detected (not safe),
0.0 when benign (is_valid=True).
"""

import time

from router.classifiers.base import BaseClassifier, ClassifierResult

_MODEL_ID = "llmguard/prompt-injection"


class LLMGuardClassifier(BaseClassifier):
    def __init__(self, threshold: float = 0.5) -> None:
        try:
            from llm_guard.input_scanners import PromptInjection  # type: ignore[import]
            from llm_guard.input_scanners.prompt_injection import (  # type: ignore[import]
                MatchType,
            )
        except ImportError as exc:
            raise ImportError(
                "llm-guard is required for LLMGuardClassifier. Install with: pip install llm-guard"
            ) from exc

        self._scanner = PromptInjection(match_type=MatchType.FULL)
        self.threshold = threshold

    async def classify(self, text: str) -> ClassifierResult:
        t0 = time.perf_counter()
        # llm-guard scanners are synchronous
        _sanitized, is_valid, risk_score = self._scanner.scan(prompt="", output=text)
        latency_ms = (time.perf_counter() - t0) * 1000

        # risk_score: 0.0 = benign, 1.0 = injection
        label = "INJECTION" if risk_score >= self.threshold else "BENIGN"
        return ClassifierResult(
            label=label,
            score=float(risk_score),
            latency_ms=latency_ms,
            model=_MODEL_ID,
        )
