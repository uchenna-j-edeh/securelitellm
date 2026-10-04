#!/usr/bin/env python3
"""Corpus scenario validator.

Each YAML file in corpus/scenarios/ is validated against the Scenario schema.
CI runs this on every PR; the same models are imported by the harness.

Usage:
    uv run python corpus/validate.py                          # validate all scenarios
    uv run python corpus/validate.py corpus/scenarios/*.yaml  # specific files
    uv run python corpus/validate.py --dump-schema            # print JSON Schema to stdout
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

# ---------------------------------------------------------------------------
# Schema models — imported by harness/runner.py at replay time
# ---------------------------------------------------------------------------

Level = Literal["L0", "L1", "L2", "L3"]
Label = Literal["attack", "benign"]
AttackClass = Literal["direct_exfil", "delayed_exfil", "mcp_pivot", "rag_poison"]
VariantTag = Literal["paraphrase", "encoding", "split"]


class ToolFunction(BaseModel):
    name: str
    arguments: str  # JSON-encoded string; parsed at harness replay time


class ToolCall(BaseModel):
    id: str
    type: Literal["function"] = "function"
    function: ToolFunction


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Optional[list[ToolCall]] = None

    @model_validator(mode="after")
    def check_role_constraints(self) -> "Message":
        if self.role == "tool" and not self.tool_call_id:
            raise ValueError("role=tool messages must include tool_call_id")
        if self.role == "assistant" and self.tool_calls is None and self.content is None:
            raise ValueError("role=assistant must have content or tool_calls")
        return self


class Turn(BaseModel):
    name: str
    is_attack_turn: bool = False
    messages: list[Message] = Field(min_length=1)


class Taxonomy(BaseModel):
    owasp_agentic: list[str] = Field(default_factory=list)
    nsa_mcp: list[str] = Field(default_factory=list)


class ExpectedDetects(BaseModel):
    # Configurations expected to produce a non-allow action on the attack turn.
    # Stateless misses multi-turn attacks by design; that absence is the finding.
    stateless: list[Level] = Field(default_factory=list)
    session: list[Level] = Field(default_factory=list)


class Scenario(BaseModel):
    """A single corpus scenario — one deterministic conversation replay."""

    model_config = {"populate_by_name": True}

    id: str = Field(pattern=r"^(sc|bn)-\d{3}$")
    name: str
    label: Label
    # "class" is a Python reserved word; the YAML key is still "class"
    scenario_class: AttackClass = Field(alias="class")
    description: str
    taxonomy: Taxonomy = Field(default_factory=Taxonomy)
    expected_detects: ExpectedDetects = Field(default_factory=ExpectedDetects)
    variant_of: Optional[str] = None
    variant_tag: Optional[VariantTag] = None
    turns: list[Turn] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_scenario(self) -> "Scenario":
        if self.label == "attack" and not any(t.is_attack_turn for t in self.turns):
            raise ValueError(
                "attack scenarios must mark at least one turn with is_attack_turn: true"
            )
        if (self.variant_of is None) != (self.variant_tag is None):
            raise ValueError("variant_of and variant_tag must both be set or both be absent")
        return self


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_file(path: Path) -> list[str]:
    """Return a list of error strings. Empty list means the file is valid."""
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(raw, dict):
        return ["YAML root must be a mapping"]
    try:
        Scenario.model_validate(raw)
        return []
    except ValidationError as exc:
        return [
            "[{}] {}".format(" → ".join(str(x) for x in e["loc"]), e["msg"]) for e in exc.errors()
        ]


def main(argv: list[str]) -> int:
    if "--dump-schema" in argv:
        print(json.dumps(Scenario.model_json_schema(by_alias=True), indent=2))
        return 0

    if len(argv) > 1 and not argv[1].startswith("-"):
        paths = [Path(p) for p in argv[1:]]
    else:
        corpus_dir = Path(__file__).parent / "scenarios"
        paths = sorted(corpus_dir.glob("*.yaml"))

    if not paths:
        print("No scenario files found.", file=sys.stderr)
        return 1

    failures = 0
    for path in paths:
        errors = validate_file(path)
        if errors:
            failures += 1
            print(f"FAIL  {path.name}")
            for e in errors:
                print(f"      {e}")
        else:
            print(f"PASS  {path.name}")

    total = len(paths)
    print(f"\n{total - failures}/{total} scenarios valid")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
