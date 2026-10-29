
"""Redis-backed SecureLiteLLM session store."""

import hashlib
import json
import math
import os
import secrets
import time
from dataclasses import asdict
from typing import Any

import redis

from router.session import (
    DEFAULT_IDLE_TTL,
    DEFAULT_TOMBSTONE_TTL,
    SESSION_ID_BYTES,
    SessionExpired,
    SessionOwnerMismatch,
    SessionState,
    SessionUnknown,
    _env_seconds,
    session_key,
)


class RedisSessionStore:
    """Shared session storage with idle expiry and tombstones."""

    def __init__(
        self,
        client: redis.Redis,
        idle_ttl: float = DEFAULT_IDLE_TTL,
        tombstone_ttl: float = DEFAULT_TOMBSTONE_TTL,
    ):
        self.client = client
        self.idle_ttl = idle_ttl
        self.tombstone_ttl = tombstone_ttl

    @classmethod
    def from_env(cls):
        client = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=os.environ["REDIS_PASSWORD"],
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=5,
        )
        client.ping()  # Fail startup if Redis is unavailable
        return cls(
            client,
            _env_seconds("SESSION_IDLE_TTL_SECONDS", DEFAULT_IDLE_TTL),
            _env_seconds(
                "SESSION_TOMBSTONE_TTL_SECONDS",
                DEFAULT_TOMBSTONE_TTL,
            ),
        )

    def _key(self, key: str) -> str:
        return f"securelitellm:session:{key}"

    def _lock(self, key: str):
        return self.client.lock(
            f"securelitellm:lock:{key}",
            timeout=30,
            blocking_timeout=5,
        )

    def _save(self, key: str, data: dict):
        # Keep the record long enough to distinguish idle expiry
        # from an unknown session.
        remaining = max(
            1,
            math.ceil(
                self.idle_ttl
                + self.tombstone_ttl
                - (time.time() - data["last_seen_at"])
            ),
        )
        self.client.set(self._key(key), json.dumps(data), ex=remaining)

    def _tombstone(self, key: str, reason: str):
        self.client.set(
            self._key(key),
            json.dumps({"expired": True, "reason": reason}),
            ex=max(1, math.ceil(self.tombstone_ttl)),
        )

    def _load(self, key: str, *, strict: bool = True):
        raw = self.client.get(self._key(key))
        if raw is None:
            if strict:
                raise SessionUnknown(key)
            return None

        data = json.loads(raw)
        if data.get("expired"):
            if strict:
                raise SessionExpired(key, data["reason"])
            return None

        if time.time() - data["last_seen_at"] > self.idle_ttl:
            self._tombstone(key, "idle")
            if strict:
                raise SessionExpired(key, "idle")
            return None

        return data

    def _refresh(self, key: str, data: dict):
        data["last_seen_at"] = time.time()
        self._save(key, data)

    def issue(self, owner: str = "") -> str:
        while True:
            raw = secrets.token_urlsafe(SESSION_ID_BYTES)
            key = session_key(raw)
            now = time.time()
            state = SessionState(
                session_id=key,
                owner=owner,
                created_at=now,
                last_seen_at=now,
            )
            created = self.client.set(
                self._key(key),
                json.dumps(asdict(state)),
                nx=True,
                ex=math.ceil(self.idle_ttl + self.tombstone_ttl),
            )
            if created:
                return raw

    def state(self, key: str) -> SessionState:
        with self._lock(key):
            data = self._load(key)
            self._refresh(key, data)
            return SessionState(**data)

    def authorize(self, key: str, owner: str) -> SessionState:
        with self._lock(key):
            data = self._load(key)
            if data["owner"] != owner:
                raise SessionOwnerMismatch(key)
            self._refresh(key, data)
            return SessionState(**data)

    def record_source(
        self, key: str, source: dict[str, Any], *, taint: bool = True
    ) -> None:
        with self._lock(key):
            data = self._load(key)
            data["sources"].append(source)
            if taint:
                data["tainted"] = True
                content_hash = source.get("content_hash")
                if not content_hash:
                    content = str(
                        source.get("content")
                        or source.get("content_for_classifier", "")
                    )
                    content_hash = hashlib.sha256(
                        content.encode()
                    ).hexdigest()
                data["tainted_spans"].append(str(content_hash))
            self._refresh(key, data)

    def record_sink(self, key: str, sink: dict[str, Any]) -> None:
        with self._lock(key):
            data = self._load(key, strict=False)
            if data is not None:
                data["sinks"].append(sink)
                self._refresh(key, data)

    def mark_sensitive(self, key: str) -> None:
        with self._lock(key):
            data = self._load(key, strict=False)
            if data is not None:
                data["sensitive"] = True
                self._refresh(key, data)

    def record_escalation(self, key: str) -> int:
        with self._lock(key):
            data = self._load(key, strict=False)
            if data is None:
                return 0
            data["escalation_count"] += 1
            self._refresh(key, data)
            return data["escalation_count"]

    def expire(self, key: str, reason: str = "ended") -> None:
        with self._lock(key):
            self._tombstone(key, reason)

    def sweep(self) -> None:
        # Redis TTL removes abandoned sessions automatically.
        pass
