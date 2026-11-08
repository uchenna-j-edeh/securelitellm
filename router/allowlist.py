"""Destination allowlist (#167): every place a send goes must be listed.

Applies to sends: tools in the "exfil" category (email, HTTP posts,
webhooks, messages), tools of unknown capability, which already count as
sinks so a new tool name fails closed, and read-named tools that name a
destination ("network", #218): every URL such a call requests, whatever the
argument is called, and every address or channel in its destination
arguments. Writes and other reads are out of scope for
now (#93).

Every destination in a send's arguments is checked, wherever it came from:
email to/cc/bcc (lists and display names included), URLs and endpoints
(matched as normalized complete URLs, including path and query), Slack channels and message
recipients. There is no exception for a destination the user typed. A send
with no destination found is not allowed (fail closed).

Policy entries (``allowed_destinations:``):

  alice@example.com          one exact address
  https://api.partner.com/v2 one exact URL (scheme, path and query included)
  #team-reports              one Slack channel

Email entries are exact addresses only; ``@example.com`` is rejected. A domain
entry would approve every mailbox at the domain, including shared inboxes,
contractors and forwarding rules nobody chose. Listing each address gives every
allowed destination an owner: if data leaks to one, the people with access to
that inbox are known.

Decision records name what was refused by domain, host or channel only, so a
full address is never logged.

User-named destinations (#212, switch ``user_named``): a send may also be
required to go only where the user asked. Each send is checked against the
user message that started its turn (the latest user message before the
assistant message that made the call). Every destination must appear there,
matched exactly as above: the full email address, the complete URL, or the exact
#channel. A destination that appears only in a tool result, or that the model
chose, is not named, so tool content can't decide that a send happens or
where it goes. An address the user named in an earlier turn doesn't count.
The user's own destinations (policy ``own_destinations:``, same entry forms)
count as named in every turn: sending to yourself isn't exfiltration.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from email.utils import getaddresses
from typing import Any, Iterator
from urllib.parse import urlsplit

from router.taint import network_targets

# Argument names that hold a destination. Values may be a string (comma or
# semicolon separated) or a list of strings.
DESTINATION_ARGS = frozenset(
    {
        "to",
        "cc",
        "bcc",
        "recipient",
        "recipients",
        "email",
        "address",
        "url",
        "uri",
        "endpoint",
        "webhook",
        "webhook_url",
        "channel",
        "destination",
        "target",
    }
)

# Destination arguments that hold a URL; call_destinations reads them as URLs.
_URL_ARGS = frozenset({"url", "uri", "endpoint", "webhook", "webhook_url"})

NO_DESTINATION = "(no destination)"

# Destinations as a user types them in a message (#212).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"'`]+")
_BARE_HOST_RE = re.compile(
    r"(?<![\w@./:-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:[/?#][^\s<>\"'`]+)?(?![\w@:-])"
)
_CHANNEL_RE = re.compile(r"(?<![\w&#])#[A-Za-z0-9][\w-]*")


def _is_url(value: str) -> bool:
    return "://" in value


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.rstrip(".").lower() if host else None


_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}


def _percent_normalized(component: str) -> str:
    """RFC 3986: decode only unreserved bytes, never delimiters such as %2F."""

    def replace(match: re.Match) -> str:
        char = chr(int(match.group()[1:], 16))
        return char if char in _UNRESERVED else match.group().upper()

    return re.sub(r"%[0-9A-Fa-f]{2}", replace, component)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4; retain repeated and trailing slashes."""
    output = ""
    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
        elif path.startswith("/./") or path == "/.":
            path = path[2:] or "/"
        elif path.startswith("/../") or path == "/..":
            path = path[3:]
            output = output.rsplit("/", 1)[0]
            if not path:
                path = "/"
        elif path in (".", ".."):
            path = ""
        else:
            end = path.find("/", 1 if path.startswith("/") else 0)
            if end == -1:
                output += path
                path = ""
            else:
                output += path[:end]
                path = path[end:]
    return output


def normalize_url(value: str, *, explicit_path: bool = False) -> str | None:
    """Exact network URL key (#218), or None for ambiguous/malformed inputs.

    Policy URLs require an explicit path (use / for a root page). Bare tool/user
    URLs keep #219's http assumption; the scheme is never ignored. Query order,
    repeated parameters, case, reserved escapes, fragments and /a versus /a/
    stay distinct.
    This changes only the comparison key, never the URL a tool will execute.
    """
    if (
        not value
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
        or any(c in value for c in '\\<>"`')
    ):
        return None
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return None
    if not _is_url(value):
        if not _BARE_HOST_RE.fullmatch(value):
            return None
        value = "http://" + value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port  # validates range and syntax
        if not host or parsed.username is not None or parsed.password is not None:
            return None
        if not re.fullmatch(r"[A-Za-z0-9.:-]+", host) or parsed.netloc.endswith(":"):
            return None
        if explicit_path and not parsed.path:
            return None
        scheme = parsed.scheme.lower()
        host = host.lower().rstrip(".")
        if not host:
            return None
        authority = f"[{host}]" if ":" in host else host
        if port is not None and port != _DEFAULT_PORTS.get(scheme):
            authority += f":{port}"
        path = _remove_dot_segments(_percent_normalized(parsed.path or "/"))
        query = _percent_normalized(parsed.query)
        fragment = _percent_normalized(parsed.fragment)
        normalized = f"{scheme}://{authority}{path}"
        if query or "?" in value.split("#", 1)[0]:
            normalized += "?" + query
        if "#" in value:
            # Kept, not dropped: HTTP clients don't send it, but a tool that
            # logs or forwards the raw URL would carry data placed there.
            normalized += "#" + fragment
        return normalized
    except ValueError:
        return None


def _typed_url(value: str) -> str:
    """Trim sentence punctuation and unmatched prose brackets from a bare token."""
    value = value.rstrip(".,;!?")
    while value and any(
        value.endswith(end) and value.count(end) > value.count(start)
        for start, end in (("(", ")"), ("[", "]"))
    ):
        value = value[:-1].rstrip(".,;!?")
    return value


def _typed_urls(text: str, pattern: re.Pattern, scheme_less: bool = False) -> Iterator[str]:
    """Normalized URLs typed in *text*. A scheme-less URL ("www.x.com/a") names
    both its http and https forms: the user chose no scheme, and models usually
    pick https. Policy entries still need an explicit scheme."""
    for match in pattern.finditer(text):
        value = match.group()
        # Backticks, quotes and angle brackets make terminal punctuation
        # intentional. URL regexes exclude quotes/brackets; strip backticks here.
        quoted = match.start() > 0 and text[match.start() - 1] in "`\"'<"
        value = value if quoted else _typed_url(value)
        normalized = normalize_url(value)
        if normalized:
            yield normalized
            if scheme_less and normalized.startswith("http://"):
                yield "https://" + normalized[len("http://") :]


# A host label fit for a decision record: DNS labels with at least one dot, or
# an IP address. Anything else (free text from an argument) is not logged.
_LOGGABLE_HOST_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z0-9-]+|\[?[0-9a-f:.]+\]?")


def _refusal_label(url: str) -> str:
    """The host to name in a refusal, or a placeholder. Decision records keep
    hosts only; a malformed URL argument such as "password=hunter2" must not
    reach them as if it were a host."""
    host = _host(url)
    if host and _LOGGABLE_HOST_RE.fullmatch(host):
        return host
    return "(unparseable url)"


@dataclass(frozen=True)
class Allowlist:
    addresses: frozenset[str]
    urls: frozenset[str]
    channels: frozenset[str]

    @classmethod
    def from_entries(cls, entries: Any) -> Allowlist:
        if not isinstance(entries, list):
            raise ValueError("allowed_destinations must be a list")
        addresses, urls, channels = set(), set(), set()
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"allowed_destinations: invalid entry {entry!r}")
            value = entry.strip()
            if value.startswith("#") and len(value) > 1:
                channels.add(value.lower())
            elif value.startswith("@"):
                raise ValueError(
                    f"allowed_destinations: {entry!r} would allow every address at the domain; "
                    "list each address (e.g. alice{entry})"
                )
            elif _is_url(value):
                url = normalize_url(value, explicit_path=True)
                if not url:
                    raise ValueError(
                        "allowed_destinations: invalid URL or missing explicit path; "
                        "list the exact endpoint (use / for the root page)"
                    )
                urls.add(url)
            elif value.count("@") == 1 and "." in value.split("@")[1]:
                addresses.add(value.lower())
            else:
                raise ValueError(
                    f"allowed_destinations: {entry!r} is not an email address, URL or #channel"
                )
        return cls(frozenset(addresses), frozenset(urls), frozenset(channels))

    @classmethod
    def named_in(cls, text: str) -> Allowlist:
        """Destinations typed in *text*: exact addresses, complete URLs and #channels.

        A scheme-less URL names its http and https forms; a bare host names
        only its root page; an email domain does not name a URL.
        """
        # Read URLs before addresses: removing an email from a URL query would
        # falsely authorize a truncated URL the user never typed (#218).
        urls = set(_typed_urls(text, _URL_RE))
        rest = _URL_RE.sub(" ", text)
        urls.update(_typed_urls(rest, _BARE_HOST_RE, scheme_less=True))
        rest = _BARE_HOST_RE.sub(" ", rest)
        addresses = {a.lower() for a in _EMAIL_RE.findall(rest)}
        rest = _EMAIL_RE.sub(" ", rest)
        channels = {c.lower() for c in _CHANNEL_RE.findall(rest)}
        return cls(frozenset(addresses), frozenset(urls), frozenset(channels))

    def __or__(self, other: Allowlist) -> Allowlist:
        return Allowlist(
            self.addresses | other.addresses,
            self.urls | other.urls,
            self.channels | other.channels,
        )

    def refused(self, destination: str) -> list[str]:
        """Labels for the parts of *destination* that are not allowed; empty if all are."""
        value = destination.strip()
        if _is_url(value):
            url = normalize_url(value)
            return [] if url and url in self.urls else [_refusal_label(value)]
        if "@" in value:
            # One or more addresses, with or without display names; the parser
            # returns the real address, e.g. attacker@evil.com from
            # "team@example.com <attacker@evil.com>".
            addresses = [a.lower() for _, a in getaddresses([value]) if a.count("@") == 1]
            if not addresses:
                return ["(unrecognised destination)"]
            return [
                "@" + addr.rsplit("@", 1)[1] for addr in addresses if addr not in self.addresses
            ]
        # A Slack channel, with or without "#".
        channel = value.lower() if value.startswith("#") else "#" + value.lower()
        return [] if channel in self.channels else [channel]

    def unlisted(self, sinks: list[dict[str, Any]]) -> list[str]:
        """Labels of every destination in *sinks* that is not allowlisted, sorted."""
        refused: set[str] = set()
        for sink in sinks:
            category = sink.get("category")
            if category not in ("exfil", "other", "network"):
                continue
            if category == "network":
                found = call_destinations(sink.get("_arguments", ""))
            else:
                found = list(destinations(sink.get("_arguments", "")))
            if not found:
                refused.add(NO_DESTINATION)
            for destination in found:
                refused.update(self.refused(destination))
        return sorted(refused)


_NOTHING = Allowlist(frozenset(), frozenset(), frozenset())


def not_user_named(sinks: list[dict[str, Any]], own: Allowlist = _NOTHING) -> list[str]:
    """Labels of every send destination the user didn't name in that turn (#212), sorted.

    *sinks* come from :func:`sinks_with_arguments`, or carry ``_user_request``
    themselves (generated calls). *own* is the user's own destinations, named
    in every turn. A send with no destination is not named (fail closed), as
    with the allowlist.
    """
    refused: set[str] = set()
    for sink in sinks:
        named = Allowlist.named_in(sink.get("_user_request", "")) | own
        refused.update(named.unlisted([sink]))
    return sorted(refused)


def message_text(message: dict[str, Any]) -> str:
    """The text of a chat message: a string, or the text parts of a content list."""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            part["text"]
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        )
    return ""


def latest_user_request(messages: list[dict[str, Any]]) -> str:
    """The text of the last user message: the request a generated call answers."""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return message_text(msg)
    return ""


def destinations(arguments: str, skip: frozenset[str] = frozenset()) -> Iterator[str]:
    """Every destination named in a tool call's JSON arguments, except in *skip*."""
    try:
        args = json.loads(arguments) if arguments else {}
    except ValueError:
        return  # unparseable arguments: held as malformed elsewhere; nothing to read here
    if not isinstance(args, dict):
        return
    for name, value in args.items():
        if str(name).lower() not in DESTINATION_ARGS or str(name).lower() in skip:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not isinstance(item, str):
                continue
            if str(name).lower() in _URL_ARGS and not _is_url(item):
                # Same scheme assumption as network_targets; malformed URLs
                # remain URL-shaped and fail closed, never become #channels.
                item = "http://" + item.strip()
            if _is_url(item) or "@" in item:
                # A URL is never split; an address list is parsed whole, so a
                # display name with a comma ("Doe, Jane" <j@x.com>) stays intact.
                parts = [item]
            else:
                parts = item.replace(";", ",").split(",")  # "#a, #b"
            yield from (part.strip() for part in parts if part.strip())


def call_destinations(arguments: Any) -> list[str]:
    """Every destination a read-named call names (#218): the URLs it requests,
    from any argument, and the addresses and channels in its destination
    arguments. URL-type arguments are read only as URLs, so a bare host
    ("www.example.com/page") is checked as a host, not as a channel.
    """
    if not isinstance(arguments, str):
        return []
    found = network_targets(arguments)
    for value in destinations(arguments, skip=_URL_ARGS):
        if not _is_url(value):
            found.append(value)
    return found


def sinks_with_arguments(
    sinks: list[dict[str, Any]], messages: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Request sinks (from classify_sinks) with their raw arguments attached.

    Each also gets ``_user_request``: the text of the user message that started
    its turn (#212). Neither key is logged.
    """
    by_id: dict[str, str] = {}
    request_by_id: dict[str, str] = {}
    user_request = ""
    for msg in messages:
        if msg.get("role") == "user":
            user_request = message_text(msg)
            continue
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            arguments = (call.get("function") or {}).get("arguments")
            by_id[call.get("id", "")] = arguments if isinstance(arguments, str) else ""
            request_by_id[call.get("id", "")] = user_request
    return [
        {
            **sink,
            "_arguments": by_id.get(sink.get("id") or "", ""),
            "_user_request": request_by_id.get(sink.get("id") or "", ""),
        }
        for sink in sinks
    ]
