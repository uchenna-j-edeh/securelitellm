"""Paired URL-mutation HTTP probes; no generated tool is ever executed."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--decision-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--probes", type=Path, default=Path(__file__).with_name("url-probes.json"))
    args = parser.parse_args()
    if urlsplit(args.proxy).hostname not in ("localhost", "127.0.0.1", "::1"):
        parser.error("only the isolated local mock stack may receive these probes")
    if args.output.exists():
        parser.error("choose a new output")
    os.environ["HARNESS_MODEL"] = "mock"
    os.environ["LITELLM_MASTER_KEY"] = "sk-exact218-eval-only"
    from harness import decisions, runner

    runner.PROXY_URL = args.proxy
    runner.DEFAULT_MODEL = "mock"
    runner.LITELLM_MASTER_KEY = "sk-exact218-eval-only"
    decisions.DECISIONS_LOG = args.decision_log
    observations = []
    for probe in json.loads(args.probes.read_text()):
        messages = [{"role": "user", "content": "Open " + probe["user_url"]}]
        session = runner._open_session(messages)
        if not session:
            raise RuntimeError("proxy did not issue a session")
        before = decisions.current_log_size()
        call = dict(
            id="generated",
            type="function",
            function=dict(
                name="get_webpage", arguments=json.dumps({"url": probe["generated_url"]})
            ),
        )
        extra = dict(
            mock_reply=dict(tool_calls=[call]),
            tools=[
                dict(
                    type="function",
                    function=dict(name="get_webpage", parameters=dict(type="object")),
                )
            ],
        )
        ok, _, _, response = runner._post_turn(messages, session, extra)
        if not ok or not response:
            raise RuntimeError("probe HTTP failure")
        choice = response["choices"][0]
        released = bool(choice["message"].get("tool_calls"))
        if not released and choice["finish_reason"] != "content_filter":
            raise RuntimeError("missing generated call without a gateway hold")
        post = decisions.wait_for_decision(
            runner.session_ref(session), before, timeout=0.25, phase="post_call"
        )
        if not post or post.get("action") not in ("hold", "execute", "block"):
            raise RuntimeError("missing or unknown post-call decision")
        observations.append(
            dict(
                id=probe["id"],
                released=released,
                finish_reason=choice["finish_reason"],
                post_action=(post or {}).get("action"),
                features=(post or {}).get("features", {}),
            )
        )
    args.output.write_text(
        json.dumps(
            dict(
                external_tools_executed=False,
                probes_sha256=hashlib.sha256(args.probes.read_bytes()).hexdigest(),
                observations=observations,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
