"""Decisions must reach the caller for the exact request, with scoped disclosure."""

import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from router.decisions import DECISION_HEADER, DecisionStore, response_value, summary
from router.session import SessionStoreUnavailable


def auth(owner="owner-a", role="internal_user"):
    return SimpleNamespace(token=owner, user_role=role, user_id="agent-a")


def record(**kw):
    return {
        "decision_id": "a" * 32,
        "ts": "2026-11-24T02:00:00+00:00",
        "session_id": "a" * 16,
        "request_id": "call",
        "phase": "pre_call",
        "action": "allow",
        "risk_score": 0,
        "risk_level": "low",
        "route": "standard",
        "enforce": True,
        **kw,
    }


@pytest.fixture()
def build_hook(monkeypatch, tmp_path):
    from router import hook as mod

    app = FastAPI()
    current_auth = [auth()]
    monkeypatch.setattr(mod, "_proxy_app_and_auth", lambda: (app, lambda: current_auth[0]))
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L3")
    monkeypatch.setenv("CLASSIFIER_BACKEND", "none")
    monkeypatch.setenv("ROUTER_ENFORCE", "true")
    monkeypatch.setenv("ROUTER_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("SECURELITELLM_EXPOSE_DECISIONS", raising=False)

    def build(rules=(), exposed=False):
        policy = {
            "controls": {"classifier": False, "allowlist": False},
            "rules": list(rules)
            or [{"id": "benign-default", "when": {"sink_requested": True}, "score": 0}],
        }
        path = tmp_path / "policy.yaml"
        path.write_text(yaml.safe_dump(policy))
        monkeypatch.setenv("POLICY_PATH", str(path))
        monkeypatch.setenv("SECURELITELLM_EXPOSE_DECISIONS", str(exposed).lower())
        return mod.RouterHook(), app, current_auth

    return build


async def pre(hook, data, caller=None):
    return await hook.async_pre_call_hook(caller or auth(), None, data, "completion")


def data(call="request", **kw):
    return {
        "litellm_call_id": call,
        "model": "llm",
        "messages": [{"role": "user", "content": "hello"}],
        **kw,
    }


@pytest.mark.asyncio
async def test_minimal_header_and_admin_history_have_matching_audit_ids(build_hook):
    hook, app, caller = build_hook()
    request = data()
    await pre(hook, request)
    headers = await hook.async_post_call_response_headers_hook(request, auth(), {})
    value = json.loads(headers[DECISION_HEADER])
    assert set(value["decisions"][0]) == {"decision_id", "action"}
    assert "risk" not in headers[DECISION_HEADER]
    from router.session import session_ref

    ref = session_ref(headers["x-agent-run-id"])
    client = TestClient(app)
    assert client.get("/securelitellm/decisions", params={"session": ref}).status_code == 403
    caller[0] = auth(role="proxy_admin_viewer")
    restored = client.get("/securelitellm/decisions", params={"session": ref}).json()["decisions"]
    assert restored[0]["decision_id"] == value["decisions"][0]["decision_id"]
    assert restored[0]["risk_score"] == 0
    audit = [json.loads(line) for line in Path(hook.config.log_path).read_text().splitlines()]
    assert restored[0]["decision_id"] == audit[-1]["decision_id"]
    assert headers["x-agent-run-id"] not in json.dumps(restored)


@pytest.mark.asyncio
async def test_demo_exposure_is_explicit_and_history_is_bound_to_key(build_hook):
    hook, app, caller = build_hook(exposed=True)
    request = data()
    await pre(hook, request)
    headers = await hook.async_post_call_response_headers_hook(request, auth(), {})
    assert json.loads(headers[DECISION_HEADER])["decisions"][0]["risk_level"] == "low"
    from router.session import session_ref

    ref = session_ref(headers["x-agent-run-id"])
    caller[0] = auth("other-owner")
    assert (
        TestClient(app).get("/securelitellm/decisions", params={"session": ref}).json()["decisions"]
        == []
    )
    caller[0] = auth()
    assert (
        len(
            TestClient(app)
            .get("/securelitellm/decisions", params={"session": ref})
            .json()["decisions"]
        )
        == 1
    )


@pytest.mark.asyncio
async def test_blocked_first_request_keeps_structured_error_and_session(build_hook):
    hook, _, _ = build_hook([{"id": "secret-rule", "when": {"sink_requested": False}, "score": 1}])
    request = data()
    from litellm.exceptions import BadRequestError

    with pytest.raises(BadRequestError) as caught:
        await pre(hook, request)
    error = caught.value
    await hook.async_post_call_failure_hook(request, error, auth())
    # This is the object LiteLLM includes under error.provider_specific_fields.
    value = error.provider_specific_fields["securelitellm_decision"]
    assert value["decisions"][0]["action"] == "block"
    assert "secret-rule" not in error.message and "score=" not in error.message
    headers = await hook.async_post_call_response_headers_hook(request, auth(), None)
    assert json.loads(headers[DECISION_HEADER]) == value
    assert "x-agent-run-id" in headers


@pytest.mark.asyncio
async def test_post_call_hold_and_block_override_pre_call_allow(build_hook):
    from litellm.exceptions import BadRequestError

    for score, expected in [(0.5, "hold"), (1, "block")]:
        hook, _, _ = build_hook(
            [{"id": "sink", "when": {"sink_requested": True}, "score": score}], exposed=True
        )
        request = data(call=str(score))
        await pre(hook, request)
        from tests.test_hook_m2 import make_response

        response = make_response("send_email", '{"to":"demo@example.test"}')
        try:
            await hook.async_post_call_success_hook(auth(), request, response)
        except BadRequestError as exc:
            assert expected == "block"
            await hook.async_post_call_failure_hook(request, exc, auth())
        value = json.loads(
            (await hook.async_post_call_response_headers_hook(request, auth(), None))[
                DECISION_HEADER
            ]
        )
        assert [r["action"] for r in value["decisions"]] == ["allow", expected]
        assert value["decisions"][-1]["phase"] == "post_call"


@pytest.mark.asyncio
async def test_forged_metadata_and_concurrent_requests_cannot_swap_decisions(build_hook):
    from router.decisions import DECISION_METADATA_KEY

    hook, _, _ = build_hook(exposed=True)
    one = data("one")
    await pre(hook, one)
    two = data("two", metadata=copy.deepcopy(one["metadata"]))
    await pre(hook, two, auth("owner-b"))
    headers = await asyncio.gather(
        hook.async_post_call_response_headers_hook(one, auth(), {}),
        hook.async_post_call_response_headers_hook(two, auth("owner-b"), {}),
    )
    assert [json.loads(h[DECISION_HEADER])["decisions"][0]["request_id"] for h in headers] == [
        "one",
        "two",
    ]
    assert one["metadata"][DECISION_METADATA_KEY] != two["metadata"][DECISION_METADATA_KEY]


def test_memory_history_retention_caps_ownership_and_deduplication():
    now = [1000.0]
    store = DecisionStore(clock=lambda: now[0], limit=5, session_limit=3)
    for n in range(8):
        store.append([record(decision_id=f"{n:032x}")], "owner-a")
    assert len(store.read("a" * 16)) == 3
    store.append([record()], "owner-b")
    store.append([record()], "owner-b")
    assert len(store.read("a" * 16, "owner-b")) == 1
    now[0] += 3601
    assert store.read("a" * 16) == []


def test_projection_excludes_prompt_tokens_arguments_and_bounds_header():
    projected = summary(record(features={"raw": "SECRET"}, tool_context={"body": "SECRET"}))
    assert "SECRET" not in json.dumps(projected)
    value = response_value([record(route="x" * 5000)], detailed=True)
    assert value["details_truncated"]
    assert len(json.dumps(value)) < 4096


def test_minimal_audit_mode_decision_cannot_claim_enforced_block():
    result = response_value([record(action="block", enforce=False)], detailed=False)
    assert result["decisions"] == [{"decision_id": "a" * 32, "action": "observe"}]


def test_locked_router_rejects_demo_disclosure(monkeypatch):
    from router.config import RouterConfig

    monkeypatch.setenv("ROUTER_LOCK", "true")
    monkeypatch.setenv("CLASSIFIER_BACKEND", "local")
    monkeypatch.setenv("ROUTER_REQUIRE_AGENT_KEY", "true")
    monkeypatch.setenv("SECURELITELLM_EXPOSE_DECISIONS", "true")
    with pytest.raises(ValueError, match="expose_decisions"):
        RouterConfig.from_env()


@pytest.mark.asyncio
async def test_history_outage_does_not_change_live_enforcement_or_report_empty_success(
    build_hook, monkeypatch
):
    hook, app, caller = build_hook()

    def unavailable(*args):
        raise SessionStoreUnavailable()

    monkeypatch.setattr(hook._decision_history, "append", unavailable)
    monkeypatch.setattr(hook._decision_history, "read", unavailable)
    request = data()
    await pre(hook, request)
    headers = await hook.async_post_call_response_headers_hook(request, auth(), {})
    value = json.loads(headers[DECISION_HEADER])
    assert value["decisions"][0]["action"] == "allow"
    assert value["history_available"] is False
    caller[0] = auth(role="proxy_admin")
    assert (
        TestClient(app).get("/securelitellm/decisions", params={"session": "a" * 16}).status_code
        == 503
    )
