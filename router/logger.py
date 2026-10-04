"""JSONL decision record emitter — one line per request."""

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any


class DecisionLogger:
    def __init__(self, path: str = "-") -> None:
        self._path = path
        self._lock = threading.Lock()
        self._file = None
        if path != "-":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._file = open(path, "a", buffering=1)  # line-buffered

    def emit(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            if self._file:
                self._file.write(line + "\n")
                # fsync ensures Docker bind-mount (VirtioFS) propagates the write
                # to the host before fast-returning actions (e.g. block) complete.
                os.fsync(self._file.fileno())
            else:
                print(line, file=sys.stdout, flush=True)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __del__(self) -> None:
        self.close()
