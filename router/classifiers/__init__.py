"""Classifier adapter interface — PromptGuard 2 and LLM Guard.

Implemented in M3. Adapters share a common async interface:
    async def score(text: str) -> ClassifierResult
Each adapter records score, label, and latency_ms.
"""
