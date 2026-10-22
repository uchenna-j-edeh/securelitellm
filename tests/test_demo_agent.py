"""Demo agent helpers."""

import pytest

from demo.agent import parse_route_header


@pytest.mark.parametrize(
    "value, expected",
    [
        ("quarantine; risk=high", ("quarantine", "high")),
        ("standard;risk=low", ("standard", "low")),
        (None, None),
        ("", None),
        ("quarantine", None),
        ("; risk=high", None),
        ("quarantine; level=high", None),
        ("quarantine; risk=", None),
    ],
)
def test_parse_route_header(value, expected):
    assert parse_route_header(value) == expected
