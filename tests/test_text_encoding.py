"""Demo code names an encoding on every text file read and write (#244).

Python on Windows defaults to cp1252, and the demo page, corpus and logs are
UTF-8: a bare read_text() made the demo UI return 500 on a Windows laptop.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = sorted(ROOT.glob("demo/*.py")) + [
    ROOT / "scripts" / name
    for name in (
        "demo_remote.py",
        "demo_agents.py",
        "demo_policy.py",
        "demo_replay.py",
        "setup_demo.py",
        "gmail_auth.py",
        "watch_decisions.py",
    )
]


def _binary_mode(call: ast.Call, mode_index: int) -> bool:
    mode = next((k.value for k in call.keywords if k.arg == "mode"), None)
    if mode is None and len(call.args) > mode_index:
        mode = call.args[mode_index]
    return isinstance(mode, ast.Constant) and "b" in str(mode.value)


def _missing_encoding(tree: ast.AST) -> list[int]:
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or any(k.arg == "encoding" for k in node.keywords):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("read_text", "write_text"):
            lines.append(node.lineno)
        elif isinstance(func, ast.Attribute) and func.attr == "open" and not _binary_mode(node, 0):
            # Path.open(mode); os.open and similar take other arguments
            if not (
                isinstance(func.value, ast.Name) and func.value.id in ("os", "io", "webbrowser")
            ):
                lines.append(node.lineno)
        elif isinstance(func, ast.Name) and func.id == "open" and not _binary_mode(node, 1):
            lines.append(node.lineno)
    return lines


def test_demo_text_io_names_an_encoding():
    missing = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in FILES
        if path.exists()
        for line in _missing_encoding(ast.parse(path.read_text(encoding="utf-8")))
    ]
    assert not missing, "text file I/O without encoding=: " + ", ".join(missing)


def test_launcher_runs_the_demo_in_utf8_mode():
    source = (ROOT / "scripts" / "demo_remote.py").read_text(encoding="utf-8")
    assert '"PYTHONUTF8": "1"' in source
