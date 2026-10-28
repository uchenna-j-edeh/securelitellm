"""Destination allowlist (#167): every place a send goes must be listed.

Applies to sends: tools in the "exfil" category (email, HTTP posts,
webhooks, messages) and tools of unknown capability, which already count as
sinks so a new tool name fails closed. Writes and reads are out of scope for
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
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from email.utils import getaddresses
from typing import Any, Iterator
from urllib.parse import urlsplit

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
            if sink.get("category") not in ("exfil", "other"):
                continue
            found = list(destinations(sink.get("_arguments", "")))
            if not found:
                refused.add(NO_DESTINATION)
            for destination in found:
                refused.update(self.refused(destination))
        return sorted(refused)


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
    """Request sinks (from classify_sinks) with their raw arguments attached."""
    by_id: dict[str, str] = {}
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            arguments = (call.get("function") or {}).get("arguments")
            by_id[call.get("id", "")] = arguments if isinstance(arguments, str) else ""
    return [{**sink, "_arguments": by_id.get(sink.get("id") or "", "")} for sink in sinks]
