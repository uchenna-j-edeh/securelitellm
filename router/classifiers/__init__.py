"""Classifier factory.

CLASSIFIER_BACKEND env var selects the backend:
  local        — self-hosted sidecar (deploy/classifier/) — recommended for prod
  promptguard  — PromptGuard 2 via Groq API (needs GROQ_API_KEY)
  llmguard     — local LLM Guard (requires pip install llm-guard)
  none         — no classification; taint-hash detection still active at L3

Swap backends by changing CLASSIFIER_BACKEND — no code changes needed.
"""

import os

from router.classifiers.base import BaseClassifier

_BACKEND_ENV = "CLASSIFIER_BACKEND"
_CACHE_SIZE_ENV = "CLASSIFIER_CACHE_SIZE"
_DEFAULT_CACHE_SIZE = 1024


def get_classifier() -> BaseClassifier | None:
    backend = os.environ.get(_BACKEND_ENV, "promptguard").lower()

    if backend == "none":
        return None

    if backend == "promptguard":
        from router.classifiers.cached import CachedClassifier
        from router.classifiers.promptguard import PromptGuardClassifier

        max_size = int(os.environ.get(_CACHE_SIZE_ENV, _DEFAULT_CACHE_SIZE))
        return CachedClassifier(PromptGuardClassifier(), max_size=max_size)

    if backend == "llmguard":
        from router.classifiers.cached import CachedClassifier
        from router.classifiers.llmguard import LLMGuardClassifier

        max_size = int(os.environ.get(_CACHE_SIZE_ENV, _DEFAULT_CACHE_SIZE))
        return CachedClassifier(LLMGuardClassifier(), max_size=max_size)

    if backend == "local":
        from router.classifiers.cached import CachedClassifier
        from router.classifiers.local import LocalClassifier

        max_size = int(os.environ.get(_CACHE_SIZE_ENV, _DEFAULT_CACHE_SIZE))
        return CachedClassifier(LocalClassifier(), max_size=max_size)

    raise ValueError(
        f"Unknown CLASSIFIER_BACKEND={backend!r}. Valid values: local, promptguard, llmguard, none"
    )
