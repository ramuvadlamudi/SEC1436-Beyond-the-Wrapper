from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import os
import sys
from typing import Any


_SEEN: set[str] = set()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _audit_dir() -> Path:
    configured = os.environ.get("ARIA_AUDIT_DIR", "data/audit")
    path = Path(configured)

    if not path.is_absolute():
        path = _project_root() / path

    path.mkdir(parents=True, exist_ok=True)
    return path


def log_suppressed_exception(exc: Any, *, component: str = "runtime") -> None:
    """
    Write suppressed exceptions to audit JSONL once per unique exception.

    Default behavior is quiet:
    - no repeated console spam
    - no customer data assumptions
    - no dataset, index, sourcetype, host, user, IP, EventCode, or use-case mapping

    Set ARIA_SUPPRESSED_EXCEPTION_STDERR=true to mirror first-seen events to stderr.
    """
    try:
        exc_type = type(exc).__name__
        exc_preview = str(exc)[:500]
        key = f"{component}:{exc_type}:{exc_preview[:300]}"

        if key in _SEEN:
            return

        _SEEN.add(key)

        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "component": component,
            "exception_type": exc_type,
            "exception_preview": exc_preview,
        }

        log_file = _audit_dir() / "suppressed-exceptions.jsonl"

        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

        if os.environ.get("ARIA_SUPPRESSED_EXCEPTION_STDERR", "").lower() in {"1", "true", "yes"}:
            print(
                "[ARIA][WARN] suppressed-exception logged:",
                repr(exc),
                file=sys.stderr,
                flush=True,
            )

    except BaseException as logging_error:
        print(
            "[ARIA][WARN] suppressed-exception logging failed:",
            repr(logging_error),
            file=sys.stderr,
            flush=True,
        )
