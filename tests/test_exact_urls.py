"""Full-URL authorization: same-host paths/queries cannot carry extra data (#218)."""

import json

import pytest

from router.allowlist import Allowlist, not_user_named
from router.taint import sink_category
from tests.test_network_reads import _call, _fetch, _sink
from tests.test_user_named import _data, _make_hook, _pre, _records


@pytest.mark.parametrize(
    "url",
    [
        "https://REPORTS.example.com:443/ingest",
        "https://reports.example.com/a/../ingest",
        "https://reports.example.com/a/%2e%2E/ingest",
        "https://reports.example.com/%69ngest",
    ],
)
def test_equivalent_endpoints_match(url):
    allow = Allowlist.from_entries(["https://reports.example.com/ingest"])
    assert allow.unlisted([_sink({"url": url})]) == []


@pytest.mark.parametrize(
    "url",
    [
        "https://reports.example.com/other",
        "https://reports.example.com/ingest/child",
        "https://reports.example.com/ingest/",
        "https://reports.example.com/Ingest",
        "https://reports.example.com/ingest?q=SYNTHETIC_SECRET",
        "https://reports.example.com/ingest?",
        "https://reports.example.com/ingest#SYNTHETIC_SECRET",
        "https://reports.example.com/ingest#",
        "http://reports.example.com/ingest",
        "https://reports.example.com:444/ingest",
        "https://reports.example.com/ingest%2Fchild",
        "https://reports.example.com//ingest",
        "https://reports.example.com/ingest%252fchild",
        "https://reports.example.com/ingest%",
        "https://reports.example.com/ingest\\child",
        "https://user:password@reports.example.com/ingest",
    ],
)
def test_same_host_does_not_authorize_a_different_or_ambiguous_request(url):
    allow = Allowlist.from_entries(["https://reports.example.com/ingest"])
    # Refusals expose only the host; the query/password must never enter evidence.
    refused = allow.unlisted([_sink({"url": url})])
    assert refused == ["reports.example.com"]


@pytest.mark.parametrize(
    "url",
    [
        "https://reports.example.com",
        "https://reports.example.com?x=1",
        "https://reports.example.com#root",
        "https://reports.example.com:bad/ingest",
        "https://reports.example.com:70000/ingest",
        "https://reports.example.com:/ingest",
        "https://a@reports.example.com/ingest",
        "https://reports.example.com/ingest%XX",
    ],
)
def test_ambiguous_policy_urls_fail_startup_without_echoing_url(url):
    with pytest.raises(ValueError, match="explicit path") as error:
        Allowlist.from_entries([url])
    assert url not in str(error.value)


def test_root_page_is_explicit_and_never_a_host_wildcard():
    allow = Allowlist.from_entries(["https://reports.example.com/"])
    assert allow.refused("https://reports.example.com") == []
    assert allow.refused("https://reports.example.com/x") == ["reports.example.com"]


def test_query_order_multiplicity_values_and_reserved_bytes_are_exact():
    allow = Allowlist.from_entries(["https://reports.example.com/search?a=One&b=%2f"])
    assert allow.refused("https://reports.example.com/search?a=%4Fne&b=%2F") == []
    for query in ("b=%2F&a=One", "a=one&b=%2F", "a=One&a=One&b=%2F", "a=One&b=/", "a=One&b=%252F"):
        assert allow.refused("https://reports.example.com/search?" + query) == [
            "reports.example.com"
        ]


@pytest.mark.parametrize(
    "user_text",
    [
        "Upload to https://reports.example.com/ingest.",
        "Upload to `https://reports.example.com/ingest`.",
        'Upload to "https://reports.example.com/ingest".',
        "Upload to <https://reports.example.com/ingest>.",
        "Upload to [the endpoint](https://reports.example.com/ingest).",
    ],
)
def test_prose_and_markdown_delimiters_do_not_change_a_typed_endpoint(user_text):
    assert not_user_named([_sink({"url": "https://reports.example.com/ingest"}, user_text)]) == []
    assert not_user_named(
        [_sink({"url": "https://reports.example.com/ingest?secret=1"}, user_text)]
    ) == ["reports.example.com"]


def test_literal_terminal_punctuation_can_be_named_with_backticks():
    named = Allowlist.named_in("Open `https://reports.example.com/report.`")
    assert named.refused("https://reports.example.com/report.") == []
    assert named.refused("https://reports.example.com/report") == ["reports.example.com"]


@pytest.mark.parametrize("prefix", ["https://", ""])
def test_an_address_inside_a_url_query_does_not_truncate_or_grant_an_address(prefix):
    url = prefix + "reports.example.com/notify?to=first.last@example.com"
    named = Allowlist.named_in("Open " + url)
    full = url if prefix else "http://" + url
    assert named.refused(full) == []
    assert named.refused(full.split("first.last")[0]) == ["reports.example.com"]
    assert named.refused("first.last@example.com") == ["@example.com"]


def test_dotted_email_local_parts_are_not_bare_urls():
    named = Allowlist.named_in("Email first.last@example.com")
    assert named.addresses == {"first.last@example.com"}
    assert not named.urls


def test_scheme_less_urls_keep_the_existing_http_assumption_in_send_and_read_tools():
    allow = Allowlist.from_entries(["http://reports.example.com/ingest?a=1,2"])
    for category in ("exfil", "network"):
        sink = dict(
            _sink(
                {"url": "reports.example.com/ingest?a=1,2"},
                "Post to reports.example.com/ingest?a=1,2",
            ),
            category=category,
        )
        assert allow.unlisted([sink]) == []
        assert not_user_named([sink]) == []
    assert allow.refused("https://reports.example.com/ingest?a=1,2") == ["reports.example.com"]


def test_own_urls_authorize_only_the_exact_endpoint():
    own = Allowlist.from_entries(["https://reports.example.com/ingest"])
    assert not_user_named([_sink({"url": "https://reports.example.com/ingest"})], own) == []
    assert not_user_named([_sink({"url": "https://reports.example.com/ingest?secret=1"})], own) == [
        "reports.example.com"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "controls", ["allowlist=on", "user_named=on", "allowlist=on,user_named=on"]
)
async def test_generated_calls_hold_same_host_query_injection_without_classifier_detection(
    monkeypatch, log_path, controls
):
    hook = _make_hook(monkeypatch, log_path, controls)
    result = await _fetch(
        hook,
        "Open https://reports.example.com/ingest",
        "https://reports.example.com/ingest?q=SYNTHETIC_SECRET",
    )
    record = _records(log_path)[-1]
    assert record["action"] == "hold"
    assert result is not None and not result.choices[0].message.tool_calls
    assert "SYNTHETIC_SECRET" not in json.dumps(record)


@pytest.mark.asyncio
async def test_pre_call_quarantines_a_mutated_user_named_url(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on,user_named=on")
    data = _data("Open https://reports.example.com/ingest")
    data["messages"].append(
        {
            "role": "assistant",
            "tool_calls": [
                _call("http_post", {"url": "https://reports.example.com/ingest?secret=1"})
            ],
        }
    )
    await _pre(hook, data)
    record = _records(log_path)[-1]
    assert record["action"] == "strip-tools"
    assert record["features"]["destination_not_allowed"] is True
    assert record["features"]["destination_not_user_named"] is True


@pytest.mark.parametrize(
    "url",
    [
        "https://reports.example.com/ingest?q=one two",
        "reports.example.com/ingest?q=one two",
        "https://reports.example.com/ingest?x=one\ntwo",
        "",
    ],
)
def test_malformed_url_arguments_cannot_skip_authorization_by_looking_like_reads(url):
    arguments = json.dumps({"url": url})
    assert sink_category("get_webpage", arguments) == "network"
    allow = Allowlist.from_entries(["https://reports.example.com/ingest"])
    assert allow.unlisted([_sink({"url": url})])


@pytest.mark.asyncio
async def test_a_generated_malformed_url_is_held(monkeypatch, log_path):
    hook = _make_hook(monkeypatch, log_path, "allowlist=on,user_named=on")
    await _fetch(
        hook,
        "Open https://reports.example.com/ingest",
        "https://reports.example.com/ingest?x=one\ntwo",
    )
    assert _records(log_path)[-1]["action"] == "hold"


# ---------------------------------------------------------------------------
# Review fixes on #229
# ---------------------------------------------------------------------------


def test_a_fragment_must_match_exactly():
    """Finding 4: a tool that logs or forwards the raw URL would carry it."""
    allow = Allowlist.from_entries(["https://reports.example.com/docs#setup"])
    assert allow.refused("https://reports.example.com/docs#setup") == []
    assert allow.refused("https://reports.example.com/docs#%73etup") == []  # unreserved escape
    for url in ("https://reports.example.com/docs", "https://reports.example.com/docs#d=secret"):
        assert allow.refused(url) == ["reports.example.com"]


@pytest.mark.parametrize(
    "value",
    ["password=hunter2", "see the doc above", "hunter2", "SYNTHETIC_SECRET token"],
)
def test_argument_text_never_enters_a_refusal_as_a_host(value):
    """Finding 1: decision records keep hosts only, never free argument text."""
    allow = Allowlist.from_entries(["https://reports.example.com/ingest"])
    for name, arguments in (("get_page", {"url": value}), ("list_links", {"link": value})):
        sink = {
            "category": sink_category(name, json.dumps(arguments)),
            "_arguments": json.dumps(arguments),
        }
        assert allow.unlisted([sink]) == ["(unparseable url)"]


def test_real_hosts_and_ips_are_still_named_in_refusals():
    allow = Allowlist.from_entries(["https://reports.example.com/ingest"])
    assert allow.refused("https://evil.example/x?d=secret") == ["evil.example"]
    assert allow.refused("http://10.0.0.5/x") == ["10.0.0.5"]


@pytest.mark.parametrize(
    "name, arguments",
    [
        ("get_server_status", {"host": "web-01"}),
        ("get_dns_record", {"domain": "example.com"}),
        ("list_links", {"website": "www.example.org"}),
    ],
)
def test_reads_with_host_or_domain_arguments_are_always_checked(name, arguments):
    """Finding 2 (documented in ADR-010): any value in a host/domain/link/website
    argument is checked, so a lookup can't reach an injected host unchecked."""
    allow = Allowlist.from_entries(["https://reports.example.com/ingest"])
    sink = {
        "category": sink_category(name, json.dumps(arguments)),
        "_arguments": json.dumps(arguments),
    }
    assert sink["category"] == "network"
    assert allow.unlisted([sink]) != []


def test_a_scheme_less_url_the_user_typed_names_https_too():
    """Finding 3: the user chose no scheme; models usually pick https."""
    text = "Post the hobbies to www.our-company.com/hobbies"
    for url in ("https://www.our-company.com/hobbies", "http://www.our-company.com/hobbies"):
        assert not_user_named([_sink({"url": url}, text)]) == []
    assert not_user_named([_sink({"url": "https://www.our-company.com/other"}, text)]) == [
        "www.our-company.com"
    ]


def test_a_typed_scheme_is_still_exact():
    text = "Post to http://www.our-company.com/hobbies"
    assert not_user_named([_sink({"url": "https://www.our-company.com/hobbies"}, text)]) == [
        "www.our-company.com"
    ]


def test_policy_entries_still_need_their_scheme():
    allow = Allowlist.from_entries(["http://reports.example.com/ingest"])
    assert allow.refused("https://reports.example.com/ingest") == ["reports.example.com"]
