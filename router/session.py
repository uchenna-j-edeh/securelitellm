"""Per-agent-run session store with TTL.

Implemented in M2. This module will:
- Derive a session ID from request metadata (x-agent-run-id header)
- Provide a get/put/expire interface backed by in-memory dict (Redis optional)
- Guarantee two concurrent runs never share state
"""
