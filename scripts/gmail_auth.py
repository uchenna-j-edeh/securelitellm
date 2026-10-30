#!/usr/bin/env python3
"""Sign in to the demo Gmail account once and store a single-scope token.

    make gmail-auth SCOPE=read    # gmail.readonly -> deploy/gmail_read_token.json
    make gmail-auth SCOPE=send    # gmail.send     -> deploy/gmail_send_token.json

Run it once per scope, signing in as the dedicated demo account each time.
Each token grants exactly one scope, so the read token cannot send and the
send token cannot read (demo/google_mail.py refuses any other token).

Needs an OAuth client of type "Desktop app" from a Google Cloud project with
the Gmail API enabled, downloaded to deploy/gmail_client_secret.json (or the
path in DEMO_GMAIL_CLIENT_SECRET). The client secret and both tokens are
git-ignored.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from demo import google_mail  # noqa: E402

DEFAULT_CLIENT_SECRET = REPO_ROOT / "deploy" / "gmail_client_secret.json"
SCOPES = {
    "read": (google_mail.READ_SCOPE, google_mail.read_token_path),
    "send": (google_mail.SEND_SCOPE, google_mail.send_token_path),
}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in SCOPES:
        print("usage: gmail_auth.py read|send", file=sys.stderr)
        return 2
    scope, token_path = SCOPES[argv[0]]
    client_secret = Path(os.environ.get("DEMO_GMAIL_CLIENT_SECRET", DEFAULT_CLIENT_SECRET))
    if not client_secret.exists():
        print(
            f"missing {client_secret}: download a 'Desktop app' OAuth client for a "
            "Google Cloud project with the Gmail API enabled",
            file=sys.stderr,
        )
        return 2

    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret), [scope])
    credentials = flow.run_local_server(port=0, open_browser=True)
    granted = set(credentials.scopes or [])
    if granted != {scope}:
        print(f"Google granted {sorted(granted)}, expected only {scope}", file=sys.stderr)
        return 1

    path = token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(credentials.to_json())
    path.chmod(0o600)
    print(f"wrote {path} ({argv[0]} only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
