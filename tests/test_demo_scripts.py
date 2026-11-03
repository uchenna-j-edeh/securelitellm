"""The demo services start as scripts, the way the Makefile runs them."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("script", ["demo/mcp_server.py", "demo/server.py"])
def test_demo_service_imports_when_run_as_a_script(script, tmp_path):
    """`python demo/<file>.py` puts demo/ on sys.path, not the repo root (#209 regression)."""
    path = ROOT / script
    probe = (
        "import runpy, sys; "
        f"sys.path[0] = {str(path.parent)!r}; "
        f"runpy.run_path({str(path)!r}, run_name='import_probe')"
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-c", probe], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
