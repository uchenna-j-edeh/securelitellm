"""Run the demo UI on a participant's laptop against the AWS deployment.

    uv run python scripts/demo_remote.py path/to/securelitellm-demo.env

The presenter makes the env file with ``scripts/aws_dryrun.sh participant
<name>``. It holds this participant's agent key, an approver key and the
proxy URL; the certificate (``cert.pem``) must sit next to it. Nothing else
from the presenter's machine is needed: no deploy/.env, no Docker.

Starts the demo tool server (demo/mcp_server.py, :8002) and the UI
(demo/server.py, http://localhost:8003), and stops both on Ctrl-C. Works on
macOS, Linux and Windows.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            raise SystemExit(f"{path}:{number}: expected KEY=VALUE")
        values[key.strip()] = value.strip()
    return values


def wait_for_port(port: int, process: subprocess.Popen, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit("the tool server exited; see its output above")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.3)
    raise SystemExit(f"the tool server did not open port {port}")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    env_file = Path(sys.argv[1]).expanduser().resolve()
    if not env_file.is_file():
        raise SystemExit(f"{env_file} not found")
    values = load_env(env_file)
    for required in ("PROXY_URL_SESSION", "DEMO_AGENT_KEY"):
        if not values.get(required):
            raise SystemExit(f"{env_file} has no {required}")
    cert = Path(values.get("SSL_CERT_FILE", "cert.pem"))
    if not cert.is_absolute():
        cert = env_file.parent / cert
    if not cert.is_file():
        raise SystemExit(f"certificate {cert} not found; keep cert.pem next to the env file")
    values["SSL_CERT_FILE"] = str(cert)

    # Stop both servers on SIGTERM as on Ctrl-C (and when SIGINT is ignored,
    # as in a background job).
    def interrupt(*_: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)

    env = {**os.environ, **values, "PYTHONPATH": str(ROOT)}
    tool_port = int(values.get("MCP_SERVER_PORT", "8002"))
    ui_port = values.get("DEMO_PORT", "8003")

    tools = subprocess.Popen(
        [sys.executable, str(ROOT / "demo" / "mcp_server.py")], cwd=ROOT, env=env
    )
    try:
        wait_for_port(tool_port, tools)
        print(f"\nSecureLiteLLM demo for agent {values.get('DEMO_AGENT_ID', '?')}")
        print(f"proxy: {values['PROXY_URL_SESSION']}")
        print(f"open http://localhost:{ui_port}  (Ctrl-C to stop)\n", flush=True)
        ui = subprocess.Popen([sys.executable, str(ROOT / "demo" / "server.py")], cwd=ROOT, env=env)
        try:
            return ui.wait()
        except KeyboardInterrupt:
            ui.terminate()
            ui.wait(timeout=10)
            return 0
    finally:
        if tools.poll() is None:
            tools.terminate()
            try:
                tools.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tools.kill()


if __name__ == "__main__":
    sys.exit(main())
