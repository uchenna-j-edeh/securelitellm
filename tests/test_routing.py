"""Admin routing table (#140): parsing, safety checks, and hook integration."""

import itertools
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from router.policy import _ALLOWED_FEATURES, RISK_LEVELS, PolicyEngine, load_policy_document
from router.routing import BLOCK_ROUTE, Route, RoutingTable, verify_model_groups
from tests._sessions import issued

_TABLE = {
    "routes": {
        "standard": {"model": "requested"},
        "hardened": {"model": "hardened"},
        "quarantine": {"model": "quarantine", "tools": "none"},
    },
    "matrix": {
        "low": {"public": "standard"},
        "elevated": {"public": "hardened"},
        "high": {"public": "quarantine"},
        "critical": "block",
    },
}


def _table(**overrides) -> RoutingTable:
    raw = {**json.loads(json.dumps(_TABLE)), **overrides}
    return RoutingTable.from_mapping(raw)


# ---------------------------------------------------------------------------
# Legacy table: identical to the pre-#140 actions
# ---------------------------------------------------------------------------


def _pre_140_action(score: float) -> str:
    """The action ladder as it was before #140 (default thresholds)."""
    if score >= 0.9:
        return "block"
    if score >= 0.7:
        return "strip-tools"
    if score >= 0.4:
        return "route-hardened"
    return "allow"


def test_legacy_table_without_routes_section():
    table = RoutingTable.from_mapping({"rules": []})
    assert table.source == "legacy"
    assert table.resolve("low") == Route(name="standard")
    assert table.resolve("elevated") == Route(name="hardened", model="hardened")
    assert table.resolve("high") == Route(name="quarantine", tools="none")
    assert table.resolve("critical") is BLOCK_ROUTE


def test_bundled_policy_routes_every_feature_combination_as_before():
    """Every combination of boolean policy features gets exactly the pre-#140 action."""
    document = load_policy_document()
    engine = PolicyEngine.from_mapping(document)
    table = RoutingTable.from_mapping(document)
    features = sorted(_ALLOWED_FEATURES)
    for values in itertools.product([False, True], repeat=len(features)):
        combo = dict(zip(features, values))
        score, level, _ = engine.assess(combo)
        assert table.resolve(level).legacy_action == _pre_140_action(score), combo


# ---------------------------------------------------------------------------
# Policy-defined table
# ---------------------------------------------------------------------------


def test_policy_table_resolves_each_level():
    table = _table()
    assert table.source == "policy"
    assert table.resolve("low").model is None
    assert table.resolve("elevated").model == "hardened"
    assert table.resolve("high").strips_tools
    assert table.resolve("high").model == "quarantine"
    assert table.resolve("critical").blocks


def test_summary_is_json_safe():
    summary = _table().summary()
    json.dumps(summary)
    assert summary["matrix"]["high"] == {"public": "quarantine"}
    assert summary["routes"]["standard"]["model"] == "requested"


@pytest.mark.parametrize(
    "overrides, error",
    [
        ({"routes": {}}, "non-empty mapping"),
        ({"routes": {"Bad Name": {"model": "x"}}}, "must match"),
        ({"routes": {"block": {"model": "x"}}}, "reserved"),
        ({"routes": {"standard": {"model": "x", "system_prompt": "hi"}}}, "unknown keys"),
        ({"routes": {"standard": {"model": ""}}}, "must name a model group"),
        ({"routes": {"standard": {"tools": "none"}}}, "must name a model group"),
        ({"routes": {"standard": {"model": "x", "tools": "some"}}}, "tools must be one of"),
        ({"matrix": {**_TABLE["matrix"], "severe": "block"}}, "unknown risk levels"),
        (
            {"matrix": {k: v for k, v in _TABLE["matrix"].items() if k != "low"}},
            "missing risk level",
        ),
        ({"matrix": {**_TABLE["matrix"], "low": {"public": "nope"}}}, "undefined route"),
        ({"matrix": {**_TABLE["matrix"], "low": {}}}, "low/public is missing"),
        ({"matrix": {**_TABLE["matrix"], "low": {"secret": "standard"}}}, "unknown data classes"),
        ({"matrix": {**_TABLE["matrix"], "low": ["standard"]}}, "route name or a mapping"),
        ({"matrix": {**_TABLE["matrix"], "critical": "quarantine"}}, "must be 'block'"),
        (
            {"matrix": {**_TABLE["matrix"], "elevated": "quarantine", "high": "hardened"}},
            "less restrictive",
        ),
    ],
)
def test_policy_table_rejects_unsafe_configuration(overrides, error):
    with pytest.raises(ValueError, match=error):
        _table(**overrides)


def test_routes_without_matrix_rejected():
    with pytest.raises(ValueError, match="both 'routes' and 'matrix'"):
        RoutingTable.from_mapping({"routes": _TABLE["routes"]})


def test_block_may_start_below_critical():
    table = _table(matrix={**_TABLE["matrix"], "high": "block"})
    assert table.resolve("high").blocks


@pytest.mark.parametrize("level", RISK_LEVELS)
def test_every_level_resolves(level):
    assert isinstance(_table().resolve(level), Route)


# ---------------------------------------------------------------------------
# Hook integration
# ---------------------------------------------------------------------------


def _write_policy(tmp_path: Path, **extra) -> Path:
    path = tmp_path / "policy.yaml"
    document = {
        "rules": [{"id": "r", "when": {"untrusted_seen": True}, "score": 0.5}],
        **extra,
    }
    path.write_text(yaml.safe_dump(document))
    return path


def _write_litellm_config(tmp_path: Path, *groups: dict) -> Path:
    path = tmp_path / "litellm_config.yaml"
    path.write_text(yaml.safe_dump({"model_list": list(groups)}))
    return path


def _group(name: str, model: str = "openai/mock-gpt-4", tool_calling: bool | None = True):
    entry = {"model_name": name, "litellm_params": {"model": model}}
    if tool_calling is not None:
        entry["model_info"] = {"supports_function_calling": tool_calling}
    return entry


def _make_hook(monkeypatch, log_path, policy_path=None, litellm_config=None):
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L0")
    monkeypatch.setenv("ROUTER_LOG_PATH", log_path)
    monkeypatch.setenv("ROUTER_ENFORCE", "true")
    if policy_path is not None:
        monkeypatch.setenv("POLICY_PATH", str(policy_path))
    if litellm_config is not None:
        monkeypatch.setenv("ROUTER_LITELLM_CONFIG", str(litellm_config))
    import router.session as sess_mod
    from router.session import SessionStore

    monkeypatch.setattr(sess_mod, "_store", SessionStore())
    from router.hook import RouterHook

    return RouterHook()


def _force_level(hook, monkeypatch, level):
    monkeypatch.setattr(hook._policy, "assess", lambda features: (0.5, level, ["forced"]))


def _data(model="groq"):
    return {
        "litellm_call_id": "req-1",
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"type": "function", "function": {"name": "send_email", "parameters": {}}}],
        "metadata": {"headers": {"x-agent-run-id": issued("routing")}},
    }


def _records(log_path):
    lines = Path(log_path).read_text().strip().splitlines()
    return [json.loads(line) for line in lines]


def test_startup_record_describes_routing(monkeypatch, log_path):
    _make_hook(monkeypatch, log_path)
    startup = _records(log_path)[0]
    assert startup["event"] == "startup"
    assert startup["routing"]["source"] == "policy"
    assert startup["routing"]["routes"]["hardened"]["model"] == "hardened"
    assert startup["routing"]["matrix"]["critical"] == {"public": "block"}


def test_invalid_routing_table_prevents_startup(monkeypatch, log_path, tmp_path):
    policy = _write_policy(
        tmp_path, routes=_TABLE["routes"], matrix={**_TABLE["matrix"], "critical": "standard"}
    )
    with pytest.raises(ValueError, match="must be 'block'"):
        _make_hook(monkeypatch, log_path, policy_path=policy)


@pytest.mark.asyncio
async def test_pre_call_record_carries_route(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path)
    _force_level(hook, monkeypatch, "elevated")
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(), "completion")
    assert result["model"] == "hardened"
    assert "tools" in result
    record = _records(log_path)[-1]
    assert record["risk_level"] == "elevated"
    assert record["data_class"] == "public"
    assert record["route"] == "hardened"
    assert record["action"] == "route-hardened"


@pytest.mark.asyncio
async def test_policy_table_controls_are_applied(monkeypatch, log_path, tmp_path):
    policy = _write_policy(
        tmp_path,
        routes={
            "standard": {"model": "requested"},
            "locked": {"model": "safe-group", "tools": "none"},
        },
        matrix={"low": "standard", "elevated": "locked", "high": "locked", "critical": "block"},
    )
    config = _write_litellm_config(tmp_path, _group("safe-group", tool_calling=False))
    hook = _make_hook(monkeypatch, log_path, policy_path=policy, litellm_config=config)
    _force_level(hook, monkeypatch, "elevated")
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(), "completion")
    assert result["model"] == "safe-group"
    assert "tools" not in result
    assert result["tool_choice"] == "none"
    record = _records(log_path)[-1]
    assert record["route"] == "locked"
    assert record["action"] == "strip-tools"


@pytest.mark.asyncio
async def test_standard_route_keeps_requested_model(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path)
    _force_level(hook, monkeypatch, "low")
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data("gpt"), "completion")
    assert result["model"] == "gpt"
    assert "tools" in result


@pytest.mark.asyncio
async def test_post_call_holds_sinks_on_any_policy_hit(monkeypatch, log_path, tmp_path):
    """Even a route with no controls holds generated sink calls once risk is elevated."""
    policy = _write_policy(
        tmp_path,
        routes={"standard": {"model": "requested"}},
        matrix={"low": "standard", "elevated": "standard", "high": "standard", "critical": "block"},
    )
    hook = _make_hook(monkeypatch, log_path, policy_path=policy)
    _force_level(hook, monkeypatch, "elevated")
    function = SimpleNamespace(name="send_email", arguments="{}")
    message = SimpleNamespace(
        content=None, tool_calls=[SimpleNamespace(id="g-1", function=function)]
    )
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls")]
    )

    held = await hook.async_post_call_success_hook(MagicMock(), _data(), response)

    assert held.choices[0].message.tool_calls is None
    record = _records(log_path)[-1]
    assert record["phase"] == "post_call"
    assert record["route"] == "standard"
    assert record["action"] == "hold"


# ---------------------------------------------------------------------------
# Model group checks (#85)
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).parent.parent


@pytest.mark.parametrize(
    "config",
    [
        "deploy/litellm_config.yaml",
        "deploy/litellm_config.local.yaml",
        "deploy/litellm_config_prod.yaml",
        "deploy/litellm_config.demo.yaml",
    ],
)
def test_every_deploy_config_serves_the_bundled_routes(config):
    table = RoutingTable.from_mapping(load_policy_document())
    verify_model_groups(table, str(_ROOT / config))


def test_bundled_policy_quarantines_in_its_own_model_group():
    table = RoutingTable.from_mapping(load_policy_document())
    assert table.resolve("high") == Route(name="quarantine", model="quarantine", tools="none")


def _model_list(config: str) -> dict[str, dict]:
    raw = yaml.safe_load((_ROOT / config).read_text())
    return {entry["model_name"]: entry["litellm_params"] for entry in raw["model_list"]}


def test_demo_config_differs_from_the_eval_config_only_in_quarantine():
    """The demo serves quarantine locally (#183); eval and CI keep the mock."""
    demo = _model_list("deploy/litellm_config.demo.yaml")
    base = _model_list("deploy/litellm_config.yaml")
    assert demo.pop("quarantine")["model"].startswith("ollama_chat/")
    assert base.pop("quarantine")["model"] == "openai/mock-gpt-4"
    assert demo == base


def test_missing_model_group_fails(tmp_path):
    config = _write_litellm_config(tmp_path, _group("standard-only"))
    with pytest.raises(RuntimeError, match="'hardened'.*not in the LiteLLM model_list"):
        verify_model_groups(_table(), str(config))


def test_route_with_tools_needs_tool_calling(tmp_path):
    config = _write_litellm_config(
        tmp_path, _group("hardened", tool_calling=False), _group("quarantine", tool_calling=False)
    )
    with pytest.raises(RuntimeError, match="'hardened' keeps tools.*without tool calling"):
        verify_model_groups(_table(), str(config))


def test_every_deployment_in_a_group_needs_tool_calling(tmp_path):
    config = _write_litellm_config(
        tmp_path,
        _group("hardened"),
        _group("hardened", model="openai/unknown-x", tool_calling=None),
        _group("quarantine"),
    )
    with pytest.raises(RuntimeError, match="unknown-x"):
        verify_model_groups(_table(), str(config))


def test_tool_calling_inferred_from_litellm(tmp_path):
    config = _write_litellm_config(
        tmp_path,
        _group("hardened", model="groq/qwen/qwen3.8-27b", tool_calling=None),
        _group("quarantine", tool_calling=False),  # strips tools: no tool calling needed
    )
    verify_model_groups(_table(), str(config))


def test_model_groups_need_a_litellm_config():
    with pytest.raises(RuntimeError, match="ROUTER_LITELLM_CONFIG must point"):
        verify_model_groups(_table(), "")


def test_requested_only_table_needs_no_litellm_config():
    table = _table(
        routes={"standard": {"model": "requested"}},
        matrix={"low": "standard", "elevated": "standard", "high": "standard", "critical": "block"},
    )
    verify_model_groups(table, "")


@pytest.mark.parametrize(
    "content, error",
    [
        (None, "Cannot read LiteLLM config"),
        ("model_list: [", "Cannot read LiteLLM config"),
        ("general_settings: {}", "has no model_list"),
        ("model_list:\n  - litellm_params: {model: x}", "malformed model_list entry"),
    ],
)
def test_unusable_litellm_config_fails(tmp_path, content, error):
    path = tmp_path / "litellm_config.yaml"
    if content is not None:
        path.write_text(content)
    with pytest.raises(RuntimeError, match=error):
        verify_model_groups(_table(), str(path))


def test_hook_refuses_to_start_without_the_hardened_group(monkeypatch, log_path, tmp_path):
    config = _write_litellm_config(tmp_path, _group("mock"))
    with pytest.raises(RuntimeError, match="'hardened'"):
        _make_hook(monkeypatch, log_path, litellm_config=config)


def test_removed_hardened_model_env_is_rejected(monkeypatch, log_path):
    monkeypatch.setenv("ROUTER_HARDENED_MODEL", "mock")
    with pytest.raises(ValueError, match="ROUTER_HARDENED_MODEL was removed"):
        _make_hook(monkeypatch, log_path)


def test_lock_rejects_policy_without_routing_table(monkeypatch, log_path, tmp_path):
    monkeypatch.setenv("ROUTER_LOCK", "true")
    monkeypatch.setenv("CLASSIFIER_BACKEND", "mock")
    with pytest.raises(ValueError, match="requires the policy to define 'routes'"):
        _make_hook(monkeypatch, log_path, policy_path=_write_policy(tmp_path))


def _fake_proxy(monkeypatch, model_names):
    router = SimpleNamespace(get_model_names=lambda team_id=None: list(model_names))
    monkeypatch.setitem(
        sys.modules, "litellm.proxy.proxy_server", SimpleNamespace(llm_router=router)
    )


@pytest.mark.asyncio
async def test_live_router_without_the_group_rejects_the_request(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path)
    _force_level(hook, monkeypatch, "elevated")
    _fake_proxy(monkeypatch, ["mock", "groq"])
    import litellm.exceptions as le

    with pytest.raises(le.BadRequestError, match="needs model group 'hardened'"):
        await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(), "completion")
    mismatch = _records(log_path)[-1]
    assert mismatch["event"] == "routing_config_mismatch"
    assert mismatch["missing_model_group"] == "hardened"


@pytest.mark.asyncio
async def test_live_router_with_the_group_routes_normally(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path)
    _force_level(hook, monkeypatch, "elevated")
    _fake_proxy(monkeypatch, ["mock", "hardened"])
    result = await hook.async_pre_call_hook(MagicMock(), MagicMock(), _data(), "completion")
    assert result["model"] == "hardened"
