"""The real-model probe must separate prevention, non-generation and failure."""

from pathlib import Path

import pytest

from harness import live
from harness.runner import load_scenario


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_MODE", "session")
    monkeypatch.setenv("ROUTER_LEVEL", "L3")
    monkeypatch.setenv("ROUTER_ENFORCE", "true")
    monkeypatch.setenv("ROUTER_LOG_PATH", str(tmp_path / "decisions.jsonl"))
    monkeypatch.setenv("CLASSIFIER_BACKEND", "mock")
    monkeypatch.setenv("ROUTER_CONTROLS", "classifier=on,allowlist=on")
    import router.session as sessions
    from router.hook import RouterHook

    monkeypatch.setattr(sessions, "_store", sessions.SessionStore())
    return RouterHook(), sessions._store


def scenario(sid):
    return load_scenario(Path("corpus/scenarios") / f"{sid}.yaml")


async def completion(data, **kwargs):
    return {
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "tc-1",
                            "type": "function",
                            "function": {
                                "name": "send_email",
                                "arguments": '{"to":"client@acme.io","body":"Synthetic summary"}',
                            },
                        }
                    ],
                },
            }
        ]
    }, {"model": "test-only"}


@pytest.mark.asyncio
async def test_actual_post_call_hook_holds_generated_unlisted_destination(runtime):
    row = await live.probe(
        scenario("bn-048"), *runtime, seed=1, model="test-only", complete=completion
    )
    assert row["outcome"] == "held"
    assert row["generated_calls"] == ["send_email"]
    assert row["decisions"][-1]["phase"] == "post_call"
    assert "destination_not_allowed" in row["decisions"][-1]["matched_rules"]


@pytest.mark.asyncio
async def test_model_non_generation_is_not_counted_as_gateway_prevention(runtime):
    async def no_call(*args, **kwargs):
        return {
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "I cannot help."}}]
        }, {}

    row = await live.probe(
        scenario("bn-048"), *runtime, seed=0, model="test-only", complete=no_call
    )
    assert row["outcome"] == "model_no_tool_call"


@pytest.mark.asyncio
async def test_provider_error_is_not_counted_as_prevention(runtime):
    async def fail(*args, **kwargs):
        raise RuntimeError("provider_http_429")

    row = await live.probe(scenario("bn-048"), *runtime, seed=0, model="test-only", complete=fail)
    assert row["outcome"] == "provider_error"
    assert row["error_type"] == "provider_http_429"


def test_dry_run_does_not_require_credentials_or_overwrite_results(tmp_path):
    path = tmp_path / "run.jsonl"
    path.write_text("previous run")
    assert live.main(["--dry-run", "--output", str(path)]) == 0
    assert path.read_text() == "previous run"


@pytest.mark.asyncio
async def test_pre_call_tool_removal_is_applied_before_model_request(runtime):
    from router.classifiers.base import ClassifierResult

    async def injected(text):
        return ClassifierResult(label="INJECTION", score=1, latency_ms=0, model="test")

    async def unexpected(*args, **kwargs):
        pytest.fail("A route that removes tools must not make a sink-generation request")

    runtime[0]._classifier.classify = injected
    row = await live.probe(
        scenario("bn-048"), *runtime, seed=0, model="test-only", complete=unexpected
    )
    assert row["outcome"] == "tools_removed"
    assert not row["model_called"]


@pytest.mark.asyncio
async def test_classifier_failure_is_not_credited_as_success(runtime):
    async def fail(text):
        raise RuntimeError("synthetic classifier outage")

    runtime[0]._classifier.classify = fail
    row = await live.probe(
        scenario("bn-048"), *runtime, seed=0, model="test-only", complete=completion
    )
    assert row["outcome"] == "classifier_error"
