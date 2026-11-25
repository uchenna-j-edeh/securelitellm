"""Decode only structured gateway response metadata, never model/tool text."""

import json
import math
import re

from router.decisions import DECISION_HEADER


def response_decisions(response) -> list[dict]:
    value = None
    try:
        header = response.headers.get(DECISION_HEADER, "")
        if header and len(header) <= 8192:
            value = json.loads(header)
        elif response.status_code >= 400:
            body = response.json()
            value = (
                body.get("error", {})
                .get("provider_specific_fields", {})
                .get("securelitellm_decision")
            )
    except (ValueError, TypeError, AttributeError):
        return []
    if not isinstance(value, dict) or value.get("version") != 1:
        return []
    records = value.get("decisions")
    if not isinstance(records, list) or len(records) > 4:
        return []
    result = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        identifier = record.get("decision_id")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
            continue
        if record.get("action") not in {
            "allow",
            "execute",
            "hold",
            "block",
            "strip-tools",
            "route-hardened",
            "observe",
        }:
            continue
        fields = (
            "decision_id",
            "action",
            "ts",
            "phase",
            "request_id",
            "session_id",
            "agent",
            "mode",
            "enforce",
            "risk_score",
            "risk_level",
            "route",
            "data_class",
            "matched_rules",
            "classifier_verdict",
        )
        clean = {key: record[key] for key in fields if key in record}
        score = clean.get("risk_score")
        if score is not None and (
            not isinstance(score, (float, int))
            or isinstance(score, bool)
            or not math.isfinite(score)
            or not 0 <= score <= 1
        ):
            clean.pop("risk_score")
        result[identifier] = clean
    return list(result.values())
