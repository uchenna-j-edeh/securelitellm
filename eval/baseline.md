# Hook Overhead Baseline (M1)

Measures the latency added by the pass-through `async_pre_call_hook` before any taint, classification, or policy logic is added. This is the control measurement all future milestones will be compared against.

## How to run

```bash
PYTHONPATH=. uv run python eval/benchmark_hook.py --n 2000
```

## Results

| Stat | Value |
|---|---|
| N requests | 2000 |
| p50 latency | 0.199 ms |
| p95 latency | 0.507 ms |
| min | 0.151 ms |
| max | 39.651 ms |

## Notes

- Measurement = time spent inside `async_pre_call_hook` only (not total round-trip)
- Each iteration: message parse + tool context extraction + JSONL write to stdout
- The max spike (39 ms) is a first-call JIT / Python import warm-up artifact; p95 is the stable figure
- Run on: MacBook (darwin), Python 3.14, no Docker overhead
- M2+ benchmarks will add session store lookups; M3 adds classifier latency
