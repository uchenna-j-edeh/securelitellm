"""scripts/demo_remote.py: the participant launcher for the AWS demo."""

from __future__ import annotations

import datetime
import ssl
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import certifi
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scripts import demo_remote


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    """A self-signed certificate for localhost, like the demo's load balancer cert."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_load_env_reads_pairs_and_skips_comments(tmp_path):
    env = tmp_path / "demo.env"
    env.write_text("# comment\n\nPROXY_URL_SESSION=https://x.example\nDEMO_PORT = 8013\nEMPTY=\n")
    assert demo_remote.load_env(env) == {
        "PROXY_URL_SESSION": "https://x.example",
        "DEMO_PORT": "8013",
        "EMPTY": "",
    }


def test_load_env_rejects_a_line_without_equals(tmp_path):
    env = tmp_path / "demo.env"
    env.write_text("PROXY_URL_SESSION=https://x.example\nnot a pair\n")
    with pytest.raises(SystemExit, match="demo.env:2"):
        demo_remote.load_env(env)


def test_trust_bundle_holds_public_cas_and_the_demo_certificate(tmp_path):
    cert, _ = _self_signed(tmp_path)
    bundle = demo_remote.trust_bundle(cert, tmp_path / ".ca-bundle.pem")

    text = bundle.read_text()
    assert text.startswith(Path(certifi.where()).read_text().rstrip("\n"))
    assert text.endswith(cert.read_text())
    public = Path(certifi.where()).read_text().count("BEGIN CERTIFICATE")
    context = ssl.create_default_context(cafile=str(bundle))
    assert len(context.get_ca_certs()) == public + 1


def test_trust_bundle_verifies_the_demo_server(tmp_path):
    """The regression: with the bundle, a TLS server using the demo cert verifies."""
    cert, key = _self_signed(tmp_path)
    bundle = demo_remote.trust_bundle(cert, tmp_path / ".ca-bundle.pem")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (http.server API)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("localhost", 0), Handler)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"https://localhost:{server.server_address[1]}/"
        client = ssl.create_default_context(cafile=str(bundle))
        with urllib.request.urlopen(url, context=client, timeout=10) as response:
            assert response.read() == b"ok"
        # The public CAs alone don't trust it, which is why the demo cert is added.
        with pytest.raises(urllib.error.URLError):
            urllib.request.urlopen(
                url, context=ssl.create_default_context(cafile=certifi.where()), timeout=10
            )
    finally:
        server.shutdown()
        server.server_close()


def test_main_points_ssl_cert_file_at_the_bundle(tmp_path, monkeypatch):
    """Both child processes get the combined bundle, never the demo cert alone."""
    cert, _ = _self_signed(tmp_path)
    env_file = tmp_path / "securelitellm-demo.env"
    env_file.write_text(
        "PROXY_URL_SESSION=https://proxy.example\nDEMO_AGENT_KEY=sk-test\nSSL_CERT_FILE=cert.pem\n"
    )
    launched: list[dict] = []

    class FakeProcess:
        def __init__(self, args, cwd, env):
            launched.append(env)

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(demo_remote.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(demo_remote, "wait_for_port", lambda port, process: None)
    monkeypatch.setattr(demo_remote.signal, "signal", lambda *args: None)
    monkeypatch.setattr(demo_remote.sys, "argv", ["demo_remote.py", str(env_file)])

    assert demo_remote.main() == 0
    assert len(launched) == 2  # tool server, then UI
    bundle = tmp_path / ".ca-bundle.pem"
    for env in launched:
        assert env["SSL_CERT_FILE"] == str(bundle)
    assert bundle.read_text().count("BEGIN CERTIFICATE") > 1


def test_main_refuses_a_missing_certificate(tmp_path, monkeypatch):
    env_file = tmp_path / "securelitellm-demo.env"
    env_file.write_text("PROXY_URL_SESSION=https://proxy.example\nDEMO_AGENT_KEY=sk-test\n")
    monkeypatch.setattr(demo_remote.sys, "argv", ["demo_remote.py", str(env_file)])
    with pytest.raises(SystemExit, match="cert.pem"):
        demo_remote.main()
