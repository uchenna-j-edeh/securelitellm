"""Content-hash cache wrapping any BaseClassifier.

Uses SHA-256 of the input text as the cache key.  A hit returns the original
result with cached=True and latency_ms=0.  The cache is an in-memory dict —
bounded by max_size with a simple LRU eviction.
"""

import hashlib
from collections import OrderedDict
from dataclasses import replace

from router.classifiers.base import BaseClassifier, ClassifierResult

_DEFAULT_MAX_SIZE = 1024


class CachedClassifier(BaseClassifier):
    def __init__(self, inner: BaseClassifier, max_size: int = _DEFAULT_MAX_SIZE) -> None:
        self._inner = inner
        self._max_size = max_size
        self._cache: OrderedDict[str, ClassifierResult] = OrderedDict()

    def _key(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    async def classify(self, text: str) -> ClassifierResult:
        key = self._key(text)
        if key in self._cache:
            self._cache.move_to_end(key)
            cached_result = self._cache[key]
            return replace(cached_result, cached=True, latency_ms=0.0)

        result = await self._inner.classify(text)

        self._cache[key] = result
        self._cache.move_to_end(key)
        if len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

        return result

    def cache_size(self) -> int:
        return len(self._cache)

    def invalidate(self, text: str) -> None:
        self._cache.pop(self._key(text), None)

    def clear(self) -> None:
        self._cache.clear()
