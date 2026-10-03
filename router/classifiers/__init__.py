"""Classifier factory.

CLASSIFIER_BACKEND env var selects the backend:
  promptguard  (default) — PromptGuard 2 via Groq API, wrapped in CachedClassifier
  llmguard               — local LLM Guard (requires pip install llm-guard)
  none                   — no classification (returns None from safe_classify)
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

    raise ValueError(
        f"Unknown CLASSIFIER_BACKEND={backend!r}. "
        "Valid values: promptguard, llmguard, none"
    )
