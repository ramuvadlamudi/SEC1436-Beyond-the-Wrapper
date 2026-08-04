from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_command(name: str, command: list[str], timeout: int = 60) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = (result.stdout or "") + (result.stderr or "")

        if result.returncode == 0:
            return True, output.strip()

        return False, output.strip()

    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def file_exists(path: str) -> bool:
    p = Path(path)
    return p.exists() and p.stat().st_size > 0


def print_status(status: str, name: str, detail: str = "") -> None:
    if detail:
        print(f"{status:<6} {name:<32} {detail}")
    else:
        print(f"{status:<6} {name}")


def load_json(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}

    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def check_service(service: str) -> tuple[bool, str]:
    ok, output = run_command(
        service,
        ["systemctl", "is-active", service],
        timeout=10,
    )

    if ok and output.strip() == "active":
        return True, "active"

    return False, output.strip() or "not active"


def latest_audit_file() -> Path:
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Path("data/audit") / f"aria-audit-{day}.jsonl"


def main() -> int:
    version = Path("product/VERSION").read_text(encoding="utf-8").strip() if Path("product/VERSION").exists() else "unknown"
    print(f"ARIA {version} Health")
    print("=" * (len(version) + 12))
    print()

    failures = 0
    warnings = 0

    manifest = load_json("product/release_manifest.json")
    safety = load_json("product/safety_policy.json")

    print("Product")
    print("-------")
    print_status("INFO", "Name", manifest.get("full_name", "ARIA"))
    print_status("INFO", "Version", manifest.get("version", "unknown"))
    print_status("INFO", "Release channel", manifest.get("release_channel", "unknown"))
    print_status("INFO", "Default mode", safety.get("default_mode", "read_only"))
    print()

    print("Required Files")
    print("--------------")

    required_files = [
        "product/VERSION",
        "product/RELEASE_CHANNEL",
        "product/PRODUCT_NAME",
        "product/release_manifest.json",
        "product/safety_policy.json",
        "product/evidence_policy.json",
        "product/risk_policy.json",
        "aria/copilot/engine.py",
        "aria/v3/orchestrator.py",
        "aria/v3/telemetry_intelligence.py",
        "aria/v3/spl_builder_agent.py",
        "aria/v3/investigation_agent.py",
        "aria/v3/triage_agent.py",
        "docs/V3_ARCHITECTURE.md",
        "docs/SAFETY_POLICY.md",
        ".env",
        "validate_product.py",
        "validate_runtime.py",
        "aria/audit_logger.py",
    ]

    for path in required_files:
        if file_exists(path):
            print_status("PASS", path)
        else:
            print_status("FAIL", path, "missing or empty")
            failures += 1

    print()

    print("Systemd Services")
    print("----------------")

    for service in ["aria-web", "aria-llm-gateway"]:
        ok, detail = check_service(service)

        if ok:
            print_status("PASS", service, detail)
        else:
            print_status("WARN", service, detail)
            warnings += 1

    print()

    print("Audit")
    print("-----")

    audit_file = latest_audit_file()

    if audit_file.exists():
        lines = audit_file.read_text(errors="replace").splitlines()
        print_status("PASS", "Audit file", str(audit_file))
        print_status("INFO", "Audit events today", str(len(lines)))
    else:
        print_status("WARN", "Audit file", f"{audit_file} not created yet")
        warnings += 1

    print()

    print("Product Validation")
    print("------------------")

    if file_exists("validate_product.py"):
        ok, output = run_command("validate_product", [sys.executable, "validate_product.py"], timeout=60)

        if ok and "ARIA_PRODUCT_VALIDATION_STATUS=PASS" in output:
            print_status("PASS", "validate_product.py")
        else:
            print_status("FAIL", "validate_product.py", "did not pass")
            print(output[-1200:])
            failures += 1
    else:
        print_status("FAIL", "validate_product.py", "missing")
        failures += 1

    print()

    print("Safe Startup Validation")
    print("-----------------------")

    if file_exists("aria_safe_startup_check.py"):
        ok, output = run_command("aria_safe_startup_check", [sys.executable, "aria_safe_startup_check.py"], timeout=60)

        if ok and "ARIA_SAFE_STARTUP_STATUS=PASS" in output:
            print_status("PASS", "aria_safe_startup_check.py")
        elif ok and "ARIA_SAFE_STARTUP_STATUS=PASS_WITH_WARNINGS" in output:
            print_status("WARN", "aria_safe_startup_check.py", "passed with warnings")
            warnings += 1
        else:
            print_status("FAIL", "aria_safe_startup_check.py", "did not pass")
            print(output[-1200:])
            failures += 1
    else:
        print_status("FAIL", "aria_safe_startup_check.py", "missing")
        failures += 1

    print()

    print("Runtime Validation")
    print("------------------")

    if file_exists("validate_runtime.py"):
        ok, output = run_command("validate_runtime", [sys.executable, "validate_runtime.py"], timeout=90)

        if ok and "ARIA_RUNTIME_VALIDATION_STATUS=PASS" in output:
            print_status("PASS", "validate_runtime.py")
        else:
            print_status("WARN", "validate_runtime.py", "runtime check did not fully pass")
            print(output[-1200:])
            warnings += 1
    else:
        print_status("WARN", "validate_runtime.py", "missing")
        warnings += 1

    print()

    print("Summary")
    print("-------")
    print(f"Failures: {failures}")
    print(f"Warnings: {warnings}")

    if failures:
        print()
        print("ARIA_HEALTH_STATUS=FAIL")
        return 1

    if warnings:
        print()
        print("ARIA_HEALTH_STATUS=PASS_WITH_WARNINGS")
        return 0

    print()
    print("ARIA_HEALTH_STATUS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
