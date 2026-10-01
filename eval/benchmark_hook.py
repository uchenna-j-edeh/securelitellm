"""Benchmark the async_pre_call_hook overhead (p50/p95 latency).

Usage:
    uv run python eval/benchmark_hook.py [--n 1000]
"""

import argparse
import asyncio
import os
import statistics
import time
from unittest.mock import MagicMock

os.environ.setdefault("ROUTER_MODE", "stateless")
os.environ.setdefault("ROUTER_LEVEL", "L0")
os.environ.setdefault("ROUTER_LOG_PATH", "-")

from router.hook import RouterHook  # noqa: E402

SAMPLE_DATA = {
    "litellm_call_id": "bench-001",
    "messages": [
        {"role": "user", "content": "summarise my emails"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "read_email", "arguments": "{}"},
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "c1",
            "content": "Email body with injected content placeholder.",
        },
    ],
    "metadata": {"headers": {"x-agent-run-id": "bench-run-001"}},
}


async def run_benchmark(n: int) -> None:
    hook = RouterHook()
    samples: list[float] = []

    for i in range(n):
        data = {**SAMPLE_DATA, "litellm_call_id": f"bench-{i:06d}"}
        t0 = time.perf_counter()
        await hook.async_pre_call_hook(MagicMock(), MagicMock(), data, "completion")
        samples.append((time.perf_counter() - t0) * 1000)

    samples.sort()
    p50 = statistics.median(samples)
    p95 = samples[int(len(samples) * 0.95)]
    print(
        f"n={n}  p50={p50:.3f}ms  p95={p95:.3f}ms  min={samples[0]:.3f}ms  max={samples[-1]:.3f}ms"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=1000)
    args = parser.parse_args()
    asyncio.run(run_benchmark(args.n))
