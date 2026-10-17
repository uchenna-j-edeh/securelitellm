"""Test helpers: map readable test session names to proxy-issued ids.

Session ids are issued by the proxy, so tests can no longer invent them.
``issued("run-x")`` issues a real id from the current store the first time a
name is used and returns the same raw id afterwards.
"""

from router.session import get_store, session_key, session_ref


def issued(name: str, owner: str = "") -> str:
    store = get_store()
    ids = store.__dict__.setdefault("_test_ids", {})
    if name not in ids:
        ids[name] = store.issue(owner)
    return ids[name]


def key(name: str) -> str:
    return session_key(issued(name))


def ref(name: str) -> str:
    return session_ref(issued(name))
