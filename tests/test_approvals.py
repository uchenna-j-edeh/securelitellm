"""Held for approval (#174): store, hook flow and admin API."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from router.approvals import ApprovalError, ApprovalStore, calls_hash, ttl_from_env
from tests._sessions import issued, key

# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _calls(to="x@evil.com"):
    return [
        {
            "id": "call-1",
            "type": "function",
            "function": {"name": "read_file", "arguments": '{"path":"a"}'},
        },
        {
            "id": "call-2",
            "type": "function",
            "function": {"name": "send_email", "arguments": json.dumps({"to": to, "body": "hi"})},
        },
    ]


def _new(store, session_key="s-key", owner="key-a"):
    return store.create(
        session_key=session_key,
        session_ref="s-ref",
        owner=owner,
        agent="agent-a",
        calls=_calls(),
        content="Sending it now.",
        summary={
            "tools": ["read_file", "send_email"],
            "matched_rules": ["destination_not_allowed"],
        },
    )


def test_an_approved_turn_is_claimed_once_with_every_call_intact():
    store = ApprovalStore()
    raw, record = _new(store)
    store.decide(record.ref, approve=True, approver="admin")

    claim = store.claim(raw, session_key="s-key", owner="key-a")
    assert claim.ok and claim.calls == _calls() and claim.content == "Sending it now."
    again = store.claim(raw, session_key="s-key", owner="key-a")
    assert (again.ok, again.status) == (False, "used")


def test_a_pending_approval_cannot_be_claimed_and_stays_pending():
    store = ApprovalStore()
    raw, record = _new(store)
    assert store.claim(raw, session_key="s-key", owner="key-a").status == "pending"
    assert store.get(record.ref).status == "pending"


@pytest.mark.parametrize("session_key,owner", [("other", "key-a"), ("s-key", "key-b")])
def test_an_approval_is_bound_to_its_session_and_key(session_key, owner):
    store = ApprovalStore()
    raw, record = _new(store)
    store.decide(record.ref, approve=True, approver="admin")
    assert store.claim(raw, session_key=session_key, owner=owner).status == "mismatch"
    assert store.claim(raw, session_key="s-key", owner="key-a").ok  # still usable by its owner


def test_a_denied_approval_is_never_usable_and_drops_its_arguments():
    store = ApprovalStore()
    raw, record = _new(store)
    store.decide(record.ref, approve=False, approver="admin")
    assert record.calls is None
    assert store.claim(raw, session_key="s-key", owner="key-a").status == "denied"


def test_an_approval_can_be_decided_only_once():
    store = ApprovalStore()
    _, record = _new(store)
    store.decide(record.ref, approve=True, approver="admin")
    with pytest.raises(ApprovalError, match="approved, not pending"):
        store.decide(record.ref, approve=False, approver="admin")


def test_approvals_expire_whether_pending_or_approved_and_are_reported_once():
    clock = _Clock()
    store = ApprovalStore(ttl=60, clock=clock)
    raw_a, a = _new(store)
    raw_b, b = _new(store)
    store.decide(b.ref, approve=True, approver="admin")
    clock.now += 61
    assert store.claim(raw_b, session_key="s-key", owner="key-a").status == "expired"
    assert {r.ref for r in store.sweep()} == {a.ref, b.ref}
    assert store.sweep() == []
    assert a.calls is None and b.calls is None
    with pytest.raises(ApprovalError, match="expired, not pending"):
        store.decide(a.ref, approve=True, approver="admin")


def test_an_unknown_or_malformed_reference_is_not_found():
    store = ApprovalStore()
    assert store.claim("forged", session_key="s-key", owner="key-a").status == "unknown"
    for ref in ("short", "0" * 16):
        with pytest.raises(ApprovalError, match="no such approval"):
            store.decide(ref, approve=True, approver="admin")


def test_the_replay_check_compares_raw_arguments_and_then_forgets_them():
    store = ApprovalStore()
    raw, record = _new(store)
    store.decide(record.ref, approve=True, approver="admin")
    claim = store.claim(raw, session_key="s-key", owner="key-a")
    reformatted = _calls()
    reformatted[1]["function"]["arguments"] = json.dumps(
        json.loads(reformatted[1]["function"]["arguments"]), indent=1
    )
    assert calls_hash(reformatted) != calls_hash(claim.calls)  # same JSON, different bytes
    assert store.verify_replay(record.ref, claim.calls)
    assert record.calls is None
    assert not store.verify_replay(record.ref, claim.calls)  # one check only


def test_concurrent_claims_replay_exactly_once():
    store = ApprovalStore()
    raw, record = _new(store)
    store.decide(record.ref, approve=True, approver="admin")

    async def claim():
        await asyncio.sleep(0)
        return store.claim(raw, session_key="s-key", owner="key-a")

    async def race():
        return await asyncio.gather(*[claim() for _ in range(20)])

    results = asyncio.run(race())
    assert sum(result.ok for result in results) == 1
    assert {result.status for result in results if not result.ok} == {"used"}


def test_the_public_view_holds_arguments_only_on_request():
    store = ApprovalStore()
    _, record = _new(store)
    assert "tool_calls" not in record.public()
    assert "x@evil.com" not in json.dumps(record.public())
    detailed = record.public(with_arguments=True)
    assert detailed["tool_calls"][1]["name"] == "send_email"
    assert "x@evil.com" in detailed["tool_calls"][1]["arguments"]


@pytest.mark.parametrize(
    "value,idle,expected",
    [("", 1800, 900.0), ("600", 1800, 600.0), ("1800", 1800, 1800.0)],
)
def test_approval_ttl_from_the_environment(value, idle, expected):
    assert ttl_from_env({"APPROVAL_TTL_SECONDS": value}, idle) == expected


@pytest.mark.parametrize("value", ["0", "-5", "soon"])
def test_a_bad_approval_ttl_stops_startup(value):
    with pytest.raises(ValueError, match="positive integer"):
        ttl_from_env({"APPROVAL_TTL_SECONDS": value}, 1800)


def test_an_approval_ttl_longer_than_the_session_timeout_stops_startup():
    with pytest.raises(ValueError, match="must not exceed SESSION_IDLE_TTL_SECONDS"):
        ttl_from_env({"APPROVAL_TTL_SECONDS": "3600"}, 1800)
    with pytest.raises(ValueError, match="must not exceed"):
        ttl_from_env({}, 600)  # the 15-minute default against a 10-minute session


# ---------------------------------------------------------------------------
# Hook flow
# ---------------------------------------------------------------------------

AGENT = SimpleNamespace(token="key-a", user_id="agent-a", user_role="internal_user")
OTHER_AGENT = SimpleNamespace(token="key-b", user_id="agent-b", user_role="internal_user")
ADMIN = SimpleNamespace(token="master", user_id="default_user_id", user_role="proxy_admin")
VIEWER = SimpleNamespace(token="viewer", user_id="auditor", user_role="proxy_admin_viewer")


class _App:
    """Records routes like FastAPI's add_api_route."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, list[str]]] = []

    def add_api_route(self, path, endpoint, methods):
        self.routes.append((path, methods))


@pytest.fixture()
def make_hook(monkeypatch, log_path):
    def make(
        controls="allowlist=on,approvals=on",
        mode="session",
        app=None,
        ttl=None,
        idle_ttl=1800,
        auth=None,
        workers=None,
    ):
        for var in ("NUM_WORKERS", "WEB_CONCURRENCY"):
            monkeypatch.delenv(var, raising=False)
        if workers is not None:
            monkeypatch.setenv("NUM_WORKERS", str(workers))
        monkeypatch.setenv("ROUTER_MODE", mode)
        monkeypatch.setenv("ROUTER_LEVEL", "L3")
        monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
        monkeypatch.setenv("ROUTER_ENFORCE", "true")
        monkeypatch.setenv("CLASSIFIER_BACKEND", "mock")
        monkeypatch.setenv("ROUTER_CONTROLS", controls)
        if ttl is not None:
            monkeypatch.setenv("APPROVAL_TTL_SECONDS", str(ttl))
        else:
            monkeypatch.delenv("APPROVAL_TTL_SECONDS", raising=False)
        import router.hook as hook_mod
        import router.session as sess_mod
        from router.session import SessionStore

        monkeypatch.setattr(sess_mod, "_store", SessionStore(idle_ttl=idle_ttl))
        target = app if app is not None else _App()
        dependency = auth if auth is not None else (lambda: None)
        monkeypatch.setattr(hook_mod, "_proxy_app_and_auth", lambda: (target, dependency))
        monkeypatch.setattr(hook_mod, "_APPROVAL_ROUTE_HOOKS", {})
        hook = hook_mod.RouterHook()
        hook.register_proxy_routes(target, dependency)
        return hook

    return make


def _records(log_path):
    lines = Path(log_path).read_text().splitlines()
    return [json.loads(ln) for ln in lines if json.loads(ln).get("event") != "startup"]


def _request(call_id, approval_id=None, stream=False, run="run-1", owner="key-a"):
    headers = {"x-agent-run-id": issued(run, owner=owner)}
    if approval_id is not None:
        headers["x-securelitellm-approval"] = approval_id
    data = {
        "litellm_call_id": call_id,
        "messages": [{"role": "user", "content": "Pay the vendor and email the confirmation."}],
        "metadata": {"headers": headers},
    }
    if stream:
        data["stream"] = True
    return data


def _model_response(to="remit@evil.com", content="Sending it now."):
    calls = [
        SimpleNamespace(
            id="call-1",
            type="function",
            function=SimpleNamespace(
                name="send_email", arguments=json.dumps({"to": to, "body": "paid"})
            ),
        )
    ]
    message = SimpleNamespace(content=content, tool_calls=calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="tool_calls")])


def _mock_path_response(data):
    """What LiteLLM returns for a request carrying mock_tool_calls or mock_response."""
    calls = [
        SimpleNamespace(
            id=c["id"],
            type=c["type"],
            function=SimpleNamespace(
                name=c["function"]["name"], arguments=c["function"]["arguments"]
            ),
        )
        for c in data.get("mock_tool_calls") or []
    ]
    content = data.get("mock_response") or "This is a mock request"
    message = SimpleNamespace(content=content, tool_calls=calls or None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")])


async def _turn(hook, data, response=None, auth=AGENT):
    """One request through both hooks; the mock path stands in for LiteLLM when used."""
    sent = await hook.async_pre_call_hook(auth, MagicMock(), data, "completion")
    if response is None or "mock_tool_calls" in sent or "mock_response" in sent:
        response = _mock_path_response(sent)
    result = await hook.async_post_call_success_hook(auth, sent, response)
    headers = await hook.async_post_call_response_headers_hook(sent, auth, result or response)
    return sent, (result if result is not None else response), headers or {}


async def _held(hook):
    """Produce a pending approval; return (approval_id, approval_ref)."""
    _, result, headers = await _turn(hook, _request("req-1"), _model_response())
    assert result.choices[0].finish_reason == "content_filter"
    assert "held the generated tool call for approval" in result.choices[0].message.content
    assert headers["x-securelitellm-approval-status"] == "pending"
    approval_id = headers["x-securelitellm-approval"]
    listing = hook.approvals_list(ADMIN)["approvals"]
    assert len(listing) == 1
    return approval_id, listing[0]["approval_ref"]


@pytest.mark.asyncio
async def test_a_hold_becomes_a_pending_approval(make_hook, log_path):
    hook = make_hook()
    approval_id, ref = await _held(hook)
    item = hook.approvals_list(ADMIN)["approvals"][0]
    assert item["agent"] == "agent-a"
    assert item["tools"] == ["send_email"]
    assert item["unlisted_destinations"] == ["@evil.com"]
    assert "destination_not_allowed" in item["matched_rules"]
    assert "remit@evil.com" in item["tool_calls"][0]["arguments"]  # admins see arguments
    assert 0 < item["expires_in_seconds"] <= 900

    post = [r for r in _records(log_path) if r["phase"] == "post_call"][-1]
    assert post["action"] == "hold"
    assert post["approval"] == {
        "approval_ref": ref,
        "event": "requested",
        "expires_in_seconds": 900,
    }
    log = Path(log_path).read_text()
    assert approval_id not in log  # only the agent holds the raw id
    assert "remit@evil.com" not in log  # arguments are never logged


@pytest.mark.asyncio
async def test_an_approved_retry_replays_the_held_turn_without_the_model(make_hook, log_path):
    hook = make_hook()
    approval_id, ref = await _held(hook)
    decided = hook.approvals_decide(ref, True, ADMIN)
    assert decided["status"] == "approved" and decided["decided_by"] == "default_user_id"

    sent, result, headers = await _turn(hook, _request("req-2", approval_id))
    assert sent["mock_tool_calls"][0]["id"] == "call-1"  # the model is not asked again
    choice = result.choices[0]
    assert choice.finish_reason == "tool_calls"
    assert choice.message.content == "Sending it now."  # the original text, not the mock filler
    assert choice.message.tool_calls[0].function.arguments == json.dumps(
        {"to": "remit@evil.com", "body": "paid"}
    )
    assert "x-securelitellm-approval" not in headers

    events = [r.get("event") for r in _records(log_path) if r["phase"] == "approval"]
    assert events == ["approved", "replay_claimed"]
    post = [r for r in _records(log_path) if r["phase"] == "post_call"][-1]
    assert post["action"] == "execute"
    assert post["approval"] == {"approval_ref": ref, "event": "replayed"}
    assert hook.approvals_list(ADMIN)["approvals"] == []


@pytest.mark.asyncio
async def test_a_second_retry_gets_the_hold_notice_not_the_stored_calls(make_hook):
    hook = make_hook()
    approval_id, ref = await _held(hook)
    hook.approvals_decide(ref, True, ADMIN)
    await _turn(hook, _request("req-2", approval_id))

    sent, result, headers = await _turn(hook, _request("req-3", approval_id))
    assert "mock_tool_calls" not in sent
    assert result.choices[0].finish_reason == "content_filter"
    assert not result.choices[0].message.tool_calls
    assert "already used" in result.choices[0].message.content
    assert headers["x-securelitellm-approval-status"] == "used"


@pytest.mark.asyncio
async def test_retrying_before_a_decision_is_answered_pending(make_hook):
    hook = make_hook()
    approval_id, ref = await _held(hook)
    _, result, headers = await _turn(hook, _request("req-2", approval_id))
    assert headers["x-securelitellm-approval-status"] == "pending"
    assert "still waiting" in result.choices[0].message.content
    assert hook.approvals_list(ADMIN)["approvals"][0]["status"] == "pending"


@pytest.mark.asyncio
async def test_a_denial_is_final_and_counts_as_an_escalation(make_hook, log_path):
    from router.session import get_store

    hook = make_hook()
    approval_id, ref = await _held(hook)
    before = get_store().state(key("run-1")).escalation_count
    decided = hook.approvals_decide(ref, False, ADMIN)
    assert decided["status"] == "denied"
    assert get_store().state(key("run-1")).escalation_count == before + 1

    sent, result, headers = await _turn(hook, _request("req-2", approval_id))
    assert "mock_tool_calls" not in sent
    assert headers["x-securelitellm-approval-status"] == "denied"
    assert "do not retry" in result.choices[0].message.content
    denied = [r for r in _records(log_path) if r.get("event") == "denied"][0]
    assert denied["escalation_count"] == before + 1


@pytest.mark.asyncio
async def test_an_expired_approval_does_not_count_against_the_agent(make_hook, log_path):
    from router.session import get_store

    hook = make_hook()
    approval_id, ref = await _held(hook)
    hook.approvals_decide(ref, True, ADMIN)
    before = get_store().state(key("run-1")).escalation_count
    now = hook._approvals._clock()
    hook._approvals._clock = lambda: now + hook._approvals.ttl + 1  # time passes

    sent, result, headers = await _turn(hook, _request("req-2", approval_id))
    assert "mock_tool_calls" not in sent
    assert headers["x-securelitellm-approval-status"] == "expired"
    assert "expired" in result.choices[0].message.content
    assert get_store().state(key("run-1")).escalation_count == before
    assert [r["event"] for r in _records(log_path) if r.get("event") == "expired"] == ["expired"]


@pytest.mark.asyncio
async def test_another_agent_cannot_use_the_approval(make_hook):
    hook = make_hook()
    approval_id, ref = await _held(hook)
    hook.approvals_decide(ref, True, ADMIN)

    data = _request("req-2", approval_id, run="run-b", owner="key-b")
    sent, result, headers = await _turn(hook, data, auth=OTHER_AGENT)
    assert "mock_tool_calls" not in sent
    assert headers["x-securelitellm-approval-status"] == "mismatch"
    # The rightful agent can still use it.
    sent, _, _ = await _turn(hook, _request("req-3", approval_id))
    assert "mock_tool_calls" in sent


@pytest.mark.asyncio
async def test_a_streaming_retry_is_refused_without_using_the_approval(make_hook):
    import litellm.exceptions as _le

    hook = make_hook()
    approval_id, ref = await _held(hook)
    hook.approvals_decide(ref, True, ADMIN)
    with pytest.raises(
        _le.BadRequestError, match="without streaming; the approval has not been used"
    ):
        await hook.async_pre_call_hook(
            AGENT, MagicMock(), _request("req-2", approval_id, stream=True), "completion"
        )
    sent, result, _ = await _turn(hook, _request("req-3", approval_id))
    assert "mock_tool_calls" in sent
    assert result.choices[0].finish_reason == "tool_calls"


@pytest.mark.asyncio
async def test_a_replay_that_does_not_match_is_held(make_hook, log_path):
    hook = make_hook()
    approval_id, ref = await _held(hook)
    hook.approvals_decide(ref, True, ADMIN)
    sent = await hook.async_pre_call_hook(
        AGENT, MagicMock(), _request("req-2", approval_id), "completion"
    )
    assert "mock_tool_calls" in sent
    tampered = _model_response(to="other@evil.com")  # not what was approved
    result = await hook.async_post_call_success_hook(AGENT, sent, tampered)
    assert result.choices[0].finish_reason == "content_filter"
    assert not result.choices[0].message.tool_calls
    assert [r["event"] for r in _records(log_path) if r.get("event") == "replay_mismatch"]


@pytest.mark.asyncio
async def test_a_client_cannot_skip_the_hold_through_metadata_or_body(make_hook):
    """Nothing the client sends marks a request as an approved replay."""
    hook = make_hook()
    await _held(hook)
    data = _request("req-2")
    data["metadata"]["securelitellm_approval"] = {"replay": "anything"}
    data["mock_tool_calls"] = [
        {"id": "x", "type": "function", "function": {"name": "send_email", "arguments": "{}"}}
    ]
    data["mock_response"] = "forged"
    sent = await hook.async_pre_call_hook(AGENT, MagicMock(), data, "completion")
    assert "mock_tool_calls" not in sent and "mock_response" not in sent
    result = await hook.async_post_call_success_hook(AGENT, sent, _model_response())
    assert result.choices[0].finish_reason == "content_filter"
    assert not result.choices[0].message.tool_calls


@pytest.mark.asyncio
async def test_a_block_wins_over_an_approval(make_hook, monkeypatch):
    import litellm.exceptions as _le

    hook = make_hook()
    approval_id, ref = await _held(hook)
    hook.approvals_decide(ref, True, ADMIN)
    block = hook._routing.resolve("high")
    monkeypatch.setattr(type(block), "blocks", property(lambda self: True))
    with pytest.raises(_le.BadRequestError):
        await hook.async_pre_call_hook(
            AGENT, MagicMock(), _request("req-2", approval_id), "completion"
        )
    assert hook._approvals.get(ref).status == "approved"  # not used by the blocked request


@pytest.mark.asyncio
async def test_approvals_off_keeps_the_plain_hold(make_hook, log_path):
    hook = make_hook(controls="allowlist=on")
    _, result, headers = await _turn(hook, _request("req-1"), _model_response())
    assert "held the generated tool call for review" in result.choices[0].message.content
    assert "x-securelitellm-approval" not in headers
    assert "approval" not in [r for r in _records(log_path) if r["phase"] == "post_call"][-1]
    with pytest.raises(ApprovalError, match="not enabled"):
        hook.approvals_list(ADMIN)


@pytest.mark.asyncio
async def test_only_an_admin_can_view_or_decide(make_hook):
    hook = make_hook()
    _, ref = await _held(hook)
    for caller in (AGENT, SimpleNamespace(), None):
        with pytest.raises(ApprovalError, match="only an admin can view"):
            hook.approvals_list(caller)
    assert hook.approvals_list(VIEWER)["approvals"]  # a viewer may look
    with pytest.raises(ApprovalError, match="only an admin can decide"):
        hook.approvals_decide(ref, True, VIEWER)
    with pytest.raises(ApprovalError, match="only an admin can decide"):
        hook.approvals_decide(ref, True, AGENT)


def test_startup_reports_the_approval_ttl_and_registers_the_admin_routes(make_hook, log_path):
    app = _App()
    make_hook(app=app, ttl=600)
    startup = json.loads(Path(log_path).read_text().splitlines()[0])
    assert startup["approval_ttl_seconds"] == 600
    assert startup["controls"]["approvals"] == "on"
    assert app.routes == [
        ("/securelitellm/decisions", ["GET"]),
        ("/securelitellm/approvals", ["GET"]),
        ("/securelitellm/approvals/{approval_ref}/approve", ["POST"]),
        ("/securelitellm/approvals/{approval_ref}/deny", ["POST"]),
    ]


def test_an_approval_ttl_past_the_session_timeout_stops_the_hook(make_hook):
    with pytest.raises(ValueError, match="must not exceed SESSION_IDLE_TTL_SECONDS"):
        make_hook(ttl=900, idle_ttl=600)


# ---------------------------------------------------------------------------
# Admin API over HTTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_admin_api_lists_approves_and_denies_over_http(make_hook):
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.testclient import TestClient

    keys = {"master": ADMIN, "agent": AGENT}

    def fake_auth(authorization: str = Header(default="")):
        caller = keys.get(authorization.removeprefix("Bearer "))
        if caller is None:
            raise HTTPException(status_code=401, detail="no key")
        return caller

    app = FastAPI()
    import router.hook as hook_mod

    hook = make_hook(app=app, auth=fake_auth)  # registers the routes on this FastAPI app
    assert hook_mod._APPROVAL_ROUTE_HOOKS[id(app)] is hook
    _, ref = await _held(hook)
    _, ref2 = await _held_second(hook)
    client = TestClient(app)
    admin = {"Authorization": "Bearer master"}

    assert client.get("/securelitellm/approvals").status_code == 401
    assert (
        client.get(
            "/securelitellm/approvals", headers={"Authorization": "Bearer agent"}
        ).status_code
        == 403
    )
    listing = client.get("/securelitellm/approvals", headers=admin).json()["approvals"]
    assert {item["approval_ref"] for item in listing} == {ref, ref2}

    approved = client.post(f"/securelitellm/approvals/{ref}/approve", headers=admin)
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert client.post(f"/securelitellm/approvals/{ref}/deny", headers=admin).status_code == 409
    denied = client.post(f"/securelitellm/approvals/{ref2}/deny", headers=admin)
    assert denied.json()["status"] == "denied"
    assert (
        client.post("/securelitellm/approvals/0000000000000000/approve", headers=admin).status_code
        == 404
    )


async def _held_second(hook):
    _, _, headers = await _turn(hook, _request("req-9", run="run-2"), _model_response())
    listing = hook.approvals_list(ADMIN)["approvals"]
    return headers["x-securelitellm-approval"], listing[-1]["approval_ref"]


# ---------------------------------------------------------------------------
# One worker only (in-process state)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("session_mode", "approvals", "env", "refused"),
    [
        (False, True, {"NUM_WORKERS": "4"}, True),
        (True, False, {"NUM_WORKERS": "2"}, True),
        (False, True, {"WEB_CONCURRENCY": "3"}, True),
        (True, True, {"NUM_WORKERS": "1"}, False),
        (True, True, {}, False),
        (False, False, {"NUM_WORKERS": "8"}, False),  # stateless, no approvals: nothing to share
    ],
)
def test_in_process_state_needs_one_worker(session_mode, approvals, env, refused):
    from router.hook import check_single_worker

    def check():
        check_single_worker(env, session_mode=session_mode, approvals=approvals)

    if refused:
        with pytest.raises(ValueError, match="one worker"):
            check()
    else:
        check()


def test_a_bad_worker_count_is_refused():
    from router.hook import check_single_worker

    with pytest.raises(ValueError, match="NUM_WORKERS must be an integer"):
        check_single_worker({"NUM_WORKERS": "four"}, session_mode=False, approvals=True)


def test_the_hook_refuses_to_start_with_approvals_on_several_workers(make_hook):
    from router.session import get_store

    if get_store().shared:
        pytest.skip("with a shared store approvals may run on several workers (#169)")
    with pytest.raises(ValueError, match="approvals: on"):
        make_hook(mode="stateless", workers=4)
    assert make_hook(mode="stateless", workers=1) is not None
