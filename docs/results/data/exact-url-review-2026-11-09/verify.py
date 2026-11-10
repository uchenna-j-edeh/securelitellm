"""Verify the #229 review replay and probe evidence without contacting any service."""

import csv
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FIELDS = (
    "action",
    "risk_level",
    "route",
    "post_action",
    "post_risk_level",
    "post_route",
    "outcome",
    "data_class",
    "matched_rules",
)


def read(name):
    return json.loads((HERE / name).read_text())


def observations(name):
    result = read(name)
    assert result["external_tools_executed"] is False
    return {row["id"]: row for row in result["observations"]}


def main():
    with (HERE / "merged-main.csv").open(newline="") as source:
        before = list(csv.DictReader(source))
    with (HERE / "fixed.csv").open(newline="") as source:
        after = list(csv.DictReader(source))
    assert len(before) == len(after) == 212
    for a, b in zip(before, after):
        assert (a["suite"], a["scenario_id"], a["turn_index"]) == (
            b["suite"],
            b["scenario_id"],
            b["turn_index"],
        )
        assert all(a[field] == b[field] for field in FIELDS)
    manifests = [read(name + ".manifest.json") for name in ("merged-main", "fixed")]
    assert manifests[0]["input_files"] == manifests[1]["input_files"]
    for name, manifest in zip(("merged-main", "fixed"), manifests):
        assert manifest["scripted_reply_canary"] is True
        assert manifest["unknown_decisions"] == manifest["proxy_http_failures"] == 0
        assert (
            manifest["output_sha256"]
            == hashlib.sha256((HERE / (name + ".csv")).read_bytes()).hexdigest()
        )

    frozen = HERE / "url-probes.json"
    assert (
        frozen.read_bytes() == (HERE.parent / "exact-url-2026-11-08/url-probes.json").read_bytes()
    )
    pre = observations("merged-main-url-probes.json")
    post = observations("fixed-url-probes.json")
    for probe in read("url-probes.json"):
        case = probe["id"]
        assert pre[case]["released"] == probe["expected_exact_release"]
        expected = False if case == "normalized-equivalent" else probe["expected_exact_release"]
        assert post[case]["released"] == expected
    assert [case for case in pre if pre[case]["released"] != post[case]["released"]] == [
        "normalized-equivalent"
    ]
    for stem, input_name in (
        ("url-probes", "url-probes.json"),
        ("review-probes", "review-probes.json"),
    ):
        for arm in ("merged-main", "fixed"):
            assert (
                read(f"{arm}-{stem}.json")["probes_sha256"]
                == hashlib.sha256((HERE / input_name).read_bytes()).hexdigest()
            )

    review_pre = observations("merged-main-review-probes.json")
    review_post = observations("fixed-review-probes.json")
    for probe in read("review-probes.json"):
        assert review_post[probe["id"]]["released"] == probe["expected_fixed_release"]
    assert review_pre["scheme-less-user-https"]["released"] is False
    assert review_post["scheme-less-user-https"]["released"] is True
    old_features = review_pre["free-argument-text"]["features"]
    new_features = review_post["free-argument-text"]["features"]
    assert "synthetic_private_argument_229" in json.dumps(old_features).lower()
    assert "synthetic_private_argument_229" not in json.dumps(new_features).lower()
    for field in ("unlisted_destinations", "unnamed_destinations"):
        assert new_features[field] == ["(unparseable url)"]

    summary = dict(
        date="2026-11-09",
        timezone="America/New_York",
        base_commit="457f7274f1e233d09c64053d7264beec07cc28a1",
        review_fixes_commit="717b8e229ec42909fa1a293f8262808bd4a2a33f",
        mode="session",
        level="L3",
        controls=manifests[0]["controls"],
        seed=0,
        external_tools_executed=False,
        paired_rows=212,
        total_replay_rows=424,
        compared_fields=FIELDS,
        replay_changes=[],
        input_hashes_equal=True,
        scripted_generation_canaries_passed=True,
        unknown_decisions=0,
        proxy_http_failures=0,
        frozen_probe_input_unchanged=True,
        frozen_probe_changes=[dict(id="normalized-equivalent", before="released", after="held")],
        review_probe_count=4,
        argument_text_redacted=True,
        all_fixed_probe_expectations_pass=True,
        source_sha256={
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for path in (
                "router/allowlist.py",
                "router/taint.py",
                "deploy/policy.yaml",
                "deploy/mock_model/main.py",
            )
        },
    )
    (HERE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("Verified 424 replay rows, 22 frozen-probe observations and 8 review-probe observations.")


if __name__ == "__main__":
    main()
