"""Source/sink taint model and cross-turn propagation.

Implemented in M2. This module will:
- Classify tool/MCP outputs by trust tier (source registry)
- Classify tool calls by exfiltration capability (sink registry)
- Propagate taint across turns within a session
- Store tainted spans (hashed + raw) for L3 content correlation
"""
