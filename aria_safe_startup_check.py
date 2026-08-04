from __future__ import annotations

import json
from pathlib import Path


PLACEHOLDER_VALUES = {
    "CHANGE_ME",
    "READ_ONLY_USER",
    "SPLUNK_SERVER",
    "OLLAMA_SERVER",
    "YOUR_USERNAME",
    "YOUR_PASSWORD",
}


REQUIRED_FILES = [
    "product/release_manifest.json",
    "product/safety_policy.json",
    "product/evidence_policy.json",
    "product/risk_policy.json",
    "product/VERSION",
    "product/RELEASE_CHANNEL",
    "aria/v3/orchestrator.py",
    "aria/v3/router.py",
    "aria/v3/telemetry_intelligence.py",
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


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    path = Path(".env")

    if not path.exists():
        return env

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")

    return env


def print_status(status: str, name: str, detail: str = "") -> None:
    if detail:
        print(f"{status:<6} {name:<35} {detail}")
    else:
        print(f"{status:<6} {name}")


def main() -> int:
    print("ARIA Safe Startup Check")
    print("=======================")
    print()

    failures = 0
    warnings = 0

    for file_path in REQUIRED_FILES:
        path = Path(file_path)

        if path.exists() and path.stat().st_size > 0:
            print_status("PASS", file_path)
        else:
            print_status("FAIL", file_path, "missing or empty")
            failures += 1

    print()

    try:
        policy = json.loads(Path("product/safety_policy.json").read_text())
        default_mode = policy.get("default_mode")
        if default_mode == "read_only":
            print_status("PASS", "Safety default mode", default_mode)
        else:
            print_status("FAIL", "Safety default mode", f"expected read_only, got {default_mode}")
            failures += 1
    except Exception as exc:
        print_status("FAIL", "Safety policy parse", str(exc))
        failures += 1

    env = load_env()

    print()

    for key in REQUIRED_ENV_KEYS:
        value = env.get(key)

        if not value:
            print_status("FAIL", key, "missing")
            failures += 1
            continue

        if value in PLACEHOLDER_VALUES:
            print_status("FAIL", key, "placeholder value still configured")
            failures += 1
            continue

        if "PASSWORD" in key or "TOKEN" in key:
            print_status("PASS", key, "[REDACTED]")
        else:
            print_status("PASS", key, value)

    print()

    audit_enabled = env.get("ARIA_AUDIT_ENABLED", "true").lower()
    audit_full_text = env.get("ARIA_AUDIT_CAPTURE_FULL_TEXT", "false").lower()

    if audit_enabled == "false":
        print_status("WARN", "Audit logging", "ARIA_AUDIT_ENABLED=false")
        warnings += 1
    else:
        print_status("PASS", "Audit logging", "enabled")

    if audit_full_text == "true":
        print_status("WARN", "Audit full text capture", "enabled; previews may contain sensitive investigation context")
        warnings += 1
    else:
        print_status("PASS", "Audit full text capture", "disabled")

    print()
    print("Summary")
    print("-------")
    print(f"Failures: {failures}")
    print(f"Warnings: {warnings}")

    if failures:
        print()
        print("ARIA_SAFE_STARTUP_STATUS=FAIL")
        return 1

    if warnings:
        print()
        print("ARIA_SAFE_STARTUP_STATUS=PASS_WITH_WARNINGS")
        return 0

    print()
    print("ARIA_SAFE_STARTUP_STATUS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
