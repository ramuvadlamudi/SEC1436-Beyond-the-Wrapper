from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

RUNTIME_PATHS = [
    ROOT / "aria",
    ROOT / "web_ui.py",
    ROOT / "aria_llm_gateway.py",
]

OLD_SPAM_PATTERNS = [
    re.compile(r'print\(\s*["\']\[ARIA\]\[WARN\] suppressed exception:', re.MULTILINE),
]


def iter_python_files():
    for base in RUNTIME_PATHS:
        if base.is_file() and base.suffix == ".py":
            yield base
        elif base.is_dir():
            for path in base.rglob("*.py"):
                if "__pycache__" in path.parts:
                    continue
                yield path


def main() -> int:
    print("ARIA Console Warning Spam Audit")
    print("===============================")
    print("Scope: product runtime only")
    print()

    failures: list[str] = []

    for path in iter_python_files():
        text = path.read_text(errors="replace")

        for pattern in OLD_SPAM_PATTERNS:
            if pattern.search(text):
                failures.append(str(path.relative_to(ROOT)))

    if failures:
        for failure in failures:
            print(f"FAIL   old console spam pattern remains: {failure}")

        print()
        print("ARIA_CONSOLE_WARNING_SPAM_AUDIT=FAIL")
        return 1

    print("PASS: No old suppressed-exception console spam print patterns found.")
    print("ARIA_CONSOLE_WARNING_SPAM_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
