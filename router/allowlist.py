"""Destination allowlist (#167): every place a send goes must be listed.

Applies to sends: tools in the "exfil" category (email, HTTP posts,
webhooks, messages), tools of unknown capability, which already count as
sinks so a new tool name fails closed, and read-named tools that request a
URL ("network", #218): every URL such a call requests is checked by host,
whatever the argument is called. Writes and other reads are out of scope for
now (#93).

Every destination in a send's arguments is checked, wherever it came from:
email to/cc/bcc (lists and display names included), URLs and endpoints
(matched on the parsed host, never on text), Slack channels and message
recipients. There is no exception for a destination the user typed. A send
with no destination found is not allowed (fail closed).

Policy entries (``allowed_destinations:``):

  alice@example.com          one exact address
  https://api.partner.com    any URL on that host (scheme and path ignored)
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
matched exactly as above: the full email address, the URL host, or the exact
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

NO_DESTINATION = "(no destination)"

# Destinations as a user types them in a message (#212).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+")
_BARE_HOST_RE = re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w-])")
_CHANNEL_RE = re.compile(r"(?<![\w&#])#[A-Za-z0-9][\w-]*")


def _is_url(value: str) -> bool:
    return "://" in value


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.rstrip(".").lower() if host else None


@dataclass(frozen=True)
class Allowlist:
    addresses: frozenset[str]
    hosts: frozenset[str]
    channels: frozenset[str]

    @classmethod
    def from_entries(cls, entries: Any) -> Allowlist:
        if not isinstance(entries, list):
            raise ValueError("allowed_destinations must be a list")
        addresses, hosts, channels = set(), set(), set()
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"allowed_destinations: invalid entry {entry!r}")
            value = entry.strip().lower()
            if value.startswith("#") and len(value) > 1:
                channels.add(value)
            elif value.startswith("@"):
                raise ValueError(
                    f"allowed_destinations: {entry!r} would allow every address at the domain; "
                    "list each address (e.g. alice{entry})"
                )
            elif _is_url(value):
                host = _host(value)
                if not host:
                    raise ValueError(f"allowed_destinations: no host in {entry!r}")
                hosts.add(host)
            elif value.count("@") == 1 and "." in value.split("@")[1]:
                addresses.add(value)
            else:
                raise ValueError(
                    f"allowed_destinations: {entry!r} is not an email address, URL or #channel"
                )
        return cls(frozenset(addresses), frozenset(hosts), frozenset(channels))

    @classmethod
    def named_in(cls, text: str) -> Allowlist:
        """The destinations a user typed in *text*: exact addresses, URL hosts, #channels.

        A bare host ("reports.example.com") counts as the host; the domain of
        an email address does not.
        """
        addresses = {a.lower() for a in _EMAIL_RE.findall(text)}
        rest = _EMAIL_RE.sub(" ", text)
        hosts = {h for h in (_host(u) for u in _URL_RE.findall(rest)) if h}
        rest = _URL_RE.sub(" ", rest)
        hosts.update(h.lower() for h in _BARE_HOST_RE.findall(rest))
        channels = {c.lower() for c in _CHANNEL_RE.findall(rest)}
        return cls(frozenset(addresses), frozenset(hosts), frozenset(channels))

    def __or__(self, other: Allowlist) -> Allowlist:
        return Allowlist(
            self.addresses | other.addresses,
            self.hosts | other.hosts,
            self.channels | other.channels,
        )

    def refused(self, destination: str) -> list[str]:
        """Labels for the parts of *destination* that are not allowed; empty if all are."""
        value = destination.strip()
        if _is_url(value):
            host = _host(value)
            return [] if host in self.hosts else [host or "(unparseable url)"]
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
                found = network_targets(sink.get("_arguments", ""))  # every URL it requests
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


def destinations(arguments: str) -> Iterator[str]:
    """Every destination named in a tool call's JSON arguments."""
    try:
        args = json.loads(arguments) if arguments else {}
    except ValueError:
        return  # unparseable arguments: held as malformed elsewhere; nothing to read here
    if not isinstance(args, dict):
        return
    for name, value in args.items():
        if str(name).lower() not in DESTINATION_ARGS:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not isinstance(item, str):
                continue
            if _is_url(item) or "@" in item:
                # A URL is never split; an address list is parsed whole, so a
                # display name with a comma ("Doe, Jane" <j@x.com>) stays intact.
                parts = [item]
            else:
                parts = item.replace(";", ",").split(",")  # "#a, #b"
            yield from (part.strip() for part in parts if part.strip())


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
