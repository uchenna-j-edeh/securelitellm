"""Risk score → routing action.

Implemented in M4. This module will:
- Load YAML rules from config
- Evaluate rules against the feature set allowed at the configured level (L0–L3)
- Return one of: allow / route-hardened / strip-tools / block
"""
