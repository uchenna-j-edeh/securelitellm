"""Who is calling: the agent behind a LiteLLM virtual key (#148).

Each agent is registered in LiteLLM as an internal user (``/user/new``) whose
``user_id`` is the agent's name, and holds its own virtual key
(``/key/generate``). LiteLLM authenticates the key and passes the row to the
hook as ``user_api_key_dict``; nothing the client sends in the request body
can change it.

The master key authenticates as ``proxy_admin`` and has no agent. With
``ROUTER_REQUIRE_AGENT_KEY=true`` it can no longer send model requests: it is
for administration (creating and revoking agent keys) only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# LiteLLM user roles that administer the proxy rather than act as an agent.
_ADMIN_ROLES = frozenset({"proxy_admin", "proxy_admin_viewer"})
_AGENT_ID_MAX = 128  # the id is logged with every decision; keep records bounded


@dataclass(frozen=True)
class Caller:
    agent: str | None  # the virtual key's user_id; None when the key has none or is an admin's
    admin: bool  # authenticated with the master key or an admin's key

    @property
    def violation(self) -> str | None:
        """Why this caller isn't an identified agent, or None if it is."""
        if self.agent is not None:
            return None
        return "admin_key" if self.admin else "no_identity"


def caller_identity(user_api_key_dict: Any) -> Caller:
    """The caller LiteLLM authenticated. Unknown shapes resolve to no identity."""
    role = getattr(user_api_key_dict, "user_role", None)
    role = getattr(role, "value", role)  # LitellmUserRoles is a str enum
    admin = isinstance(role, str) and role in _ADMIN_ROLES
    user_id = getattr(user_api_key_dict, "user_id", None)
    agent = None
    if not admin and isinstance(user_id, str) and user_id.strip():
        agent = user_id.strip()[:_AGENT_ID_MAX]
    return Caller(agent=agent, admin=admin)
