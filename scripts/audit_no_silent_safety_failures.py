from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATHS = [
    ROOT / "aria",
    ROOT / "web_ui.py",
    ROOT / "aria_llm_gateway.py",
]

SILENT_PATTERNS = [
    re.compile(r"(?m)^([ \t]*)except Exception:\n[ \t]*pass[ \t]*(#.*)?$"),
    re.compile(r"(?m)^([ \t]*)except Exception as [A-Za-z_][A-Za-z0-9_]*:\n[ \t]*pass[ \t]*(#.*)?$"),
]


def iter_runtime_files():
    for base in RUNTIME_PATHS:
        if base.is_file() and base.suffix == ".py":
            yield base
        elif base.is_dir():
            for path in base.rglob("*.py"):
                if "__pycache__" not in path.parts:
                    yield path


def main() -> int:
    failures = []

    print("ARIA Silent Safety Failure Audit")
    print("===============================")
    print("Scope: complete product runtime, including aria/copilot")
    print()

    for path in iter_runtime_files():
        text = path.read_text(errors="ignore")
        for pattern in SILENT_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                failures.append((str(path.relative_to(ROOT)), line_no, match.group(0).strip()))

    if failures:
        print("FAIL: Silent exception swallowing found.")
        print()
        for file_name, line_no, text in failures:
            print(f"{file_name}:{line_no}")
            print(f"  {text[:240]}")
            print()
        print("ARIA_SILENT_SAFETY_FAILURE_AUDIT=FAIL")
        return 1

    print("PASS: No silent except/pass blocks found in product runtime.")
    print("ARIA_SILENT_SAFETY_FAILURE_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
