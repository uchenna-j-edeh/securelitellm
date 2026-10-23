"""Sensitive-data detector for data classification (#181).

A deterministic regex detector: no service, reproducible in the eval. It reports
which detectors matched a request, never the matched text, so decision records
and logs carry no sensitive data themselves.

Detectors (feature name → what it matches):

  api_key_detected          provider API keys and tokens by their known prefixes
  private_key_detected      PEM private-key blocks
  credential_url_detected   URLs with an embedded password (scheme://user:pass@host)
  ssn_detected              US Social Security numbers (AAA-GG-SSSS, valid ranges)
  card_number_detected      payment card numbers that pass the Luhn check
  email_detected            email addresses
  phone_detected            phone numbers

The policy's data_classes rules decide which detectors make a request
sensitive. The bundled policy uses only the high-confidence ones: emails and
phone numbers appear in most agent traffic, so they are recorded but do not
change the data class.

What is scanned: user messages and tool results, where an agent picks up data.
Sink-result echoes (receipts of the agent's own sends) are first-party and
skipped, as in taint tracking.
"""

from __future__ import annotations

import re
from typing import Any

from router.taint import classify_sources, is_trusted_source

DETECTORS: tuple[str, ...] = (
    "api_key_detected",
    "private_key_detected",
    "credential_url_detected",
    "ssn_detected",
    "card_number_detected",
    "email_detected",
    "phone_detected",
)

_API_KEY = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-(?:live-|test-|proj-|ant-|prod-)?[A-Za-z0-9_-]{16,}"  # OpenAI/Anthropic-style
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"  # Stripe
    r"|gsk_[A-Za-z0-9]{20,}"  # Groq
    r"|gh[pousr]_[A-Za-z0-9]{36,}"  # GitHub
    r"|github_pat_[A-Za-z0-9_]{40,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"  # GitLab
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"  # Slack
    r"|AKIA[0-9A-Z]{16}"  # AWS access key id
    r"|AIza[0-9A-Za-z_-]{35}"  # Google API key
    r")"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_CREDENTIAL_URL = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]+:[^\s/@]+@[^\s/@]+")
_SSN = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
_CARD_CANDIDATE = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<![\w-])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w-])")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _has_card_number(text: str) -> bool:
    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and len(set(digits)) > 1 and _luhn_ok(digits):
            return True
    return False


def detect(text: str) -> set[str]:
    """The detectors that match *text*."""
    found: set[str] = set()
    if _API_KEY.search(text):
        found.add("api_key_detected")
    if _PRIVATE_KEY.search(text):
        found.add("private_key_detected")
    if _CREDENTIAL_URL.search(text):
        found.add("credential_url_detected")
    if _SSN.search(text):
        found.add("ssn_detected")
    if _has_card_number(text):
        found.add("card_number_detected")
    if _EMAIL.search(text):
        found.add("email_detected")
    if _PHONE.search(text):
        found.add("phone_detected")
    return found


def _text(content: Any) -> str:
    """Message content as text, including the text parts of multimodal content."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        )
    return ""


def scan_messages(messages: list[dict[str, Any]]) -> dict[str, bool]:
    """Detector features for a request: user messages and untrusted tool results."""
    trusted_ids = {s["tool_call_id"] for s in classify_sources(messages) if is_trusted_source(s)}
    found: set[str] = set()
    for msg in messages:
        role = msg.get("role")
        if role == "user" or (role == "tool" and msg.get("tool_call_id") not in trusted_ids):
            found |= detect(_text(msg.get("content")))
    return {name: name in found for name in DETECTORS}
