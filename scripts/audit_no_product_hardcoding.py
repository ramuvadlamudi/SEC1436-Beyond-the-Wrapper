from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

RUNTIME_PATHS = [
    ROOT / "aria",
    ROOT / "web_ui.py",
    ROOT / "aria_llm_gateway.py",
]

FORBIDDEN_PATTERNS = {
    "hardcoded_dataset_index": [
        r"\bbotsv3\b",
        r"\bwindows_dummy\b",
    ],
    "hardcoded_sourcetype_or_source": [
        r"\bwinhostmon\b",
        r"\bwineventlog:security\b",
        r"\bXmlWinEventLog\b",
        r"\bstream:mysql\b",
        r"\baws:elb:accesslogs\b",
        r"\bdummy:network\b",
    ],
    "hardcoded_demo_entity": [
        r"\bWIN-DUMMY-ENDPOINT-[0-9]+\b",
    ],
    "hardcoded_infrastructure_ip": [
        r"\b10\.66\.212\.[0-9]+\b",
    ],
    "hardcoded_specific_field": [
        r"\bfailed_auth_count\b",
    ],
    "hardcoded_numeric_event_identifier": [
        r"EventCode\s*=?\s*[\"']?\d+",
        r"\bevent\s*id\s*=?\s*[\"']?\d+",
    ],
    "hardcoded_usecase_mapping": [
        r"privilege escalation\s*=",
        r"failed logon\s*=",
        r"scheduled task persistence\s*=",
        r"data exfiltration\s*=",
        r"dns tunnell?ing\s*=",
    ],
}


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

    print("ARIA Product Hardcoding Audit")
    print("=============================")
    print("Scope: complete product runtime, including aria/copilot")
    print()

    for path in iter_runtime_files():
        rel = path.relative_to(ROOT)
        for line_no, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
            for category, patterns in FORBIDDEN_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, line, flags=re.IGNORECASE):
                        failures.append(
                            {
                                "file": str(rel),
                                "line": line_no,
                                "category": category,
                                "pattern": pattern,
                                "text": line.strip()[:260],
                            }
                        )

    if failures:
        print("FAIL: Runtime hardcoding found.")
        print()
        for item in failures:
            print(f"{item['file']}:{item['line']} [{item['category']}]")
            print(f"  pattern: {item['pattern']}")
            print(f"  text: {item['text']}")
            print()
        print("ARIA_PRODUCT_HARDCODING_AUDIT=FAIL")
        return 1

    print("PASS: No forbidden product-runtime hardcoding patterns found.")
    print("ARIA_PRODUCT_HARDCODING_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
