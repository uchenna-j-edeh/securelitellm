"""Protect investigation evidence from label inversion, dropped attacks and errors."""

import json
from argparse import Namespace
from pathlib import Path

import httpx
import pytest

from eval.classifier_probes import build_length_probes, build_probes
from eval.classifier_reliability import (
    HostedScorer,
    digest,
    load_probes,
    rates,
    run,
    summarize,
    transform,
)

CORPUS = Path(__file__).parents[1] / "eval/probes/classifier-190.jsonl"


def test_frozen_corpus_and_paired_formats():
    probes = load_probes(CORPUS)
    assert probes == build_probes()
    assert len(probes) == 116
    for fmt in {p["format"] for p in probes if p["group"] == "format"}:
        labels = [p["label"] for p in probes if p["group"] == "format" and p["format"] == fmt]
        assert labels.count("BENIGN") == labels.count("INJECTION") == 2
    length = load_probes(CORPUS.with_name("classifier-190-length.jsonl"))
    assert length == build_length_probes()
    assert len(length) == 16


def test_normalization_candidates_retain_their_known_limitations():
    probes = {p["id"]: p for p in load_probes(CORPUS)}
    key_attack = transform(probes["metadata-json-key"], "current")
    assert "Ignore all previous instructions" in key_attack
    assert "mandatory audit" in transform(probes["metadata-nested-json"], "current")
    for location in ("attribute", "comment", "script"):
        probe = probes["metadata-html-" + location]
        assert "Ignore all previous instructions" in transform(probe, "current")
        assert "Ignore all previous instructions" not in transform(probe, "visible-html")
    for name in ("invoice", "deadline", "override", "workflow"):
        assert (
            transform(probes["format-base64-" + name], "base64-decoded")
            == probes["format-plain-" + name]["text"]
        )


def test_errors_are_not_detections_and_threshold_uses_attack_probability():
    rows = [
        dict(expected="BENIGN", label="BENIGN", injection_probability=0.01),
        dict(expected="BENIGN", label="INJECTION", injection_probability=0.6),
        dict(expected="INJECTION", label="INJECTION", injection_probability=0.95),
        dict(expected="INJECTION", label="BENIGN", injection_probability=0.4),
        dict(expected="INJECTION", error="http", http_status=400),
    ]
    assert rates(rows) == dict(
        total=5,
        scored=4,
        errors=1,
        benign=2,
        attacks=2,
        fp=1,
        fn=1,
        tp=1,
        fpr=0.5,
        detection_rate=0.5,
    )
    assert rates(rows, 0.9)["fp"] == 0
    assert rates(rows, 0.9)["tp"] == 1


def hosted(monkeypatch, backend, response):
    monkeypatch.setenv("TEST_PROBE_KEY", "fake-only")
    scorer = HostedScorer(
        backend, "synthetic-model", "https://api.example/classify", "TEST_PROBE_KEY"
    )
    scorer.client.close()
    requests = []

    def handle(request):
        requests.append(json.loads(request.content))
        return response

    scorer.client = httpx.Client(transport=httpx.MockTransport(handle))
    return scorer, requests


def test_promptguard_score_is_probability_not_predicted_label_confidence(monkeypatch):
    scorer, requests = hosted(
        monkeypatch,
        "promptguard",
        httpx.Response(200, json={"choices": [{"message": {"content": "0.01"}}]}),
    )
    result = scorer.score("Invoice paid")
    assert result["label"] == "BENIGN"
    assert result["injection_probability"] == 0.01
    assert requests[0]["messages"] == [{"role": "user", "content": "Invoice paid"}]
    assert "tools" not in requests[0]


@pytest.mark.parametrize("value", ["NaN", "-0.1", "1.1", "INJECTION"])
def test_promptguard_rejects_invalid_probabilities(monkeypatch, value):
    scorer, _ = hosted(
        monkeypatch,
        "promptguard",
        httpx.Response(200, json={"choices": [{"message": {"content": value}}]}),
    )
    with pytest.raises(ValueError):
        scorer.score("Invoice paid")


def test_hosted_errors_and_judge_do_not_fabricate_probabilities(monkeypatch):
    scorer, _ = hosted(
        monkeypatch, "promptguard", httpx.Response(400, text="private provider error")
    )
    assert scorer.score("text") == dict(error="http", http_status=400, attempts=1)
    scorer, requests = hosted(
        monkeypatch,
        "judge",
        httpx.Response(200, json={"choices": [{"message": {"content": '{"label":"BENIGN"}'}}]}),
    )
    result = scorer.score("Please reply by Friday")
    assert result["label"] == "BENIGN"
    assert "injection_probability" not in result
    assert requests[0]["messages"][0]["role"] == "system"
    assert "tools" not in requests[0]
    result.update(
        strategy="current", expected="BENIGN", group="format", format="plain", split="challenge"
    )
    assert "thresholds" not in summarize([result])["current"]


def test_duplicate_probe_id_fails(tmp_path):
    probe = build_probes()[0]
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps(probe) + "\n" + json.dumps(probe))
    with pytest.raises(ValueError, match="duplicate"):
        load_probes(path)


def test_retry_keeps_successes_and_original_errors(tmp_path, monkeypatch):
    import eval.classifier_reliability as module

    probes = build_probes()[:2]
    corpus = tmp_path / "probes.jsonl"
    corpus.write_text("\n".join(json.dumps(p) for p in probes) + "\n")
    prior = tmp_path / "first.jsonl"
    header = dict(
        backend="judge",
        model="synthetic-model",
        strategies=["current"],
        endpoint="https://api.example/classify",
        judge_prompt=module.JUDGE_PROMPT,
        temperature=0,
        corpus_sha256=digest(corpus.read_bytes()),
    )
    rows = [
        dict(
            id=p["id"],
            strategy="current",
            group=p["group"],
            format=p["format"],
            split=p["split"],
            expected=p["label"],
            input_sha256=digest(transform(p, "current").encode()),
        )
        for p in probes
    ]
    rows[0].update(label="BENIGN", latency_ms=1)
    rows[1].update(error="http", http_status=429)
    prior.write_text("\n".join(json.dumps(p) for p in [header, *rows]) + "\n")
    original = prior.read_bytes()
    calls = []

    class Scorer:
        metadata = dict(model="synthetic-model")

        def __init__(self, *args):
            pass

        def score(self, text, chunks):
            calls.append(text)
            return dict(label="BENIGN", latency_ms=1)

    monkeypatch.setattr(module, "HostedScorer", Scorer)
    args = Namespace(
        corpus=corpus,
        output=tmp_path / "retry.jsonl",
        backend="judge",
        model="synthetic-model",
        strategies="current",
        url="https://api.example/classify",
        api_key_env="UNUSED",
        retry_from=prior,
    )
    assert run(args) == 0
    assert calls == [transform(probes[1], "current")]
    assert prior.read_bytes() == original
    result = [json.loads(line) for line in args.output.read_text().splitlines()]
    assert result[0]["retry_parent_sha256"] == digest(original)
    assert result[1]["reused"] is True
    assert "error" not in result[2]
    args.output = tmp_path / "mismatch.jsonl"
    args.url = "https://different.example/classify"
    with pytest.raises(ValueError, match="does not match"):
        run(args)
