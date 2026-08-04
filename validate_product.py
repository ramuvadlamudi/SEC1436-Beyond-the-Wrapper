from __future__ import annotations

import json
import os
from pathlib import Path


REQUIRED_FILES = [
    "product/VERSION",
    "product/RELEASE_CHANNEL",
    "product/PRODUCT_NAME",
    "product/release_manifest.json",
    "product/safety_policy.json",
    "product/evidence_policy.json",
    "product/risk_policy.json",
    "docs/SAFETY_POLICY.md",
    "docs/V3_ARCHITECTURE.md",
    "docs/V3_ACCEPTANCE.md",
    "aria/v3/orchestrator.py",
    "aria/v3/telemetry_intelligence.py",
    "aria/v3/spl_builder_agent.py",
    "aria/v3/investigation_agent.py",
    "aria/v3/triage_agent.py",
    ".env",
]

REQUIRED_ENV_KEYS = [
    "SPLUNK_URL",
    "SPLUNK_USERNAME",
    "SPLUNK_PASSWORD",
    "OLLAMA_URL",
    "OLLAMA_FAST_MODEL",
    "OLLAMA_REASONING_MODEL",
    "OLLAMA_EMBEDDING_MODEL",
]


def load_env(path: str = ".env") -> dict[str, str]:
    values: dict[str, str] = {}

    p = Path(path)
    if not p.exists():
        return values

    for line in p.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")

    return values


def check_file(path: str) -> bool:
    p = Path(path)
    return p.exists() and p.stat().st_size > 0


def check_json(path: str) -> bool:
    try:
        json.loads(Path(path).read_text())
        return True
    except Exception:
        return False


def status_line(status: str, name: str, detail: str = "") -> None:
    if detail:
        print(f"{status:<6} {name} - {detail}")
    else:
        print(f"{status:<6} {name}")


def main() -> int:
    version = Path("product/VERSION").read_text(encoding="utf-8").strip() if Path("product/VERSION").exists() else "unknown"
    print(f"ARIA {version} Product Validation")
    print("=" * (len(version) + 24))
    print()

    failures = 0
    warnings = 0

    for file_path in REQUIRED_FILES:
        if check_file(file_path):
            status_line("PASS", file_path)
        else:
            status_line("FAIL", file_path, "missing or empty")
            failures += 1

    print()

    for json_path in ["product/release_manifest.json", "product/safety_policy.json", "product/evidence_policy.json", "product/risk_policy.json"]:
        if check_file(json_path) and check_json(json_path):
            status_line("PASS", json_path, "valid JSON")
        else:
            status_line("FAIL", json_path, "invalid JSON")
            failures += 1

    print()

    env = load_env()

    for key in REQUIRED_ENV_KEYS:
        value = env.get(key)

        if value:
            if "PASSWORD" in key or "TOKEN" in key:
                status_line("PASS", key, "[REDACTED]")
            else:
                status_line("PASS", key, value)
        else:
            status_line("FAIL", key, "missing from .env")
            failures += 1

    print()

    audit_dir = Path(os.getenv("ARIA_AUDIT_DIR", "data/audit"))
    audit_dir.mkdir(parents=True, exist_ok=True)

    if audit_dir.exists():
        status_line("PASS", "Audit directory", str(audit_dir))
    else:
        status_line("FAIL", "Audit directory", "could not create")
        failures += 1

    print()
    print("Summary")
    print("-------")
    print(f"Failures: {failures}")
    print(f"Warnings: {warnings}")

    if failures:
        print()
        print("ARIA_PRODUCT_VALIDATION_STATUS=FAIL")
        return 1

    print()
    print("ARIA_PRODUCT_VALIDATION_STATUS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
