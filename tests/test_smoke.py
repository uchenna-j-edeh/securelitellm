"""Smoke tests — verify the package structure is importable and intact."""


def test_router_package_imports():
    import router  # noqa: F401
    import router.classifiers  # noqa: F401
    import router.hook  # noqa: F401
    import router.policy  # noqa: F401
    import router.session  # noqa: F401
    import router.taint  # noqa: F401


def test_router_submodules_exist():
    import importlib

    for mod in [
        "router.hook",
        "router.session",
        "router.taint",
        "router.policy",
        "router.classifiers",
    ]:
        assert importlib.util.find_spec(mod) is not None, f"{mod} not found"
