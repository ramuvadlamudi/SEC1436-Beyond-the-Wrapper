from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REQUIRED_FILES = [
    "product/VERSION", "product/RELEASE_CHANNEL", "product/PRODUCT_NAME",
    "product/release_manifest.json", "product/safety_policy.json", "product/evidence_policy.json", "product/risk_policy.json",
    "docs/ARCHITECTURE.md", "docs/V3_ARCHITECTURE.md", "docs/V3_RELEASE_NOTES.md", "docs/V3_ACCEPTANCE.md",
    "docs/INSTALLATION.md", "docs/CONFIGURATION.md", "docs/TROUBLESHOOTING.md",
    "docs/GITHUB_UI_PUBLISHING.md", "docs/REPOSITORY_CONTENTS.md", "docs/RC11_DEMO_PROMPTS.txt",
    "docs/SEC1436_THREE_PATTERN_ARCHITECTURE.md", "docs/PATTERN_COMPARISON.md", "docs/SEC1436_DEMO_RUNBOOK.md",
    "patterns/README.md", "patterns/pattern-a-ai-toolkit/README.md",
    "patterns/pattern-a-ai-toolkit/USE_CASES.md", "patterns/pattern-a-ai-toolkit/VALIDATION_REPORT.md",
    "patterns/pattern-c-dsdl-rag/README.md",
    "patterns/pattern-c-dsdl-rag/CAPABILITIES_TO_TRY_NEXT.md",
    "aria/copilot/engine.py", "aria/v3/orchestrator.py", "aria/v3/router.py",
    "aria/v3/telemetry_intelligence.py", "aria/v3/conversation_agent.py",
    "aria/v3/deliverable_agent.py",
    "aria/v3/reference_knowledge.py", "product/knowledge/reference_cards.json",
    "aria/v3/spl_builder_agent.py", "aria/v3/investigation_agent.py", "aria/v3/triage_agent.py",
    "scripts/deploy_v3_release.py", "scripts/live_v3_acceptance.py",
    "scripts/test_v3_conversation.py", "scripts/test_v3_reference_knowledge.py",
    "scripts/test_v3_deliverables.py",
    "scripts/test_v3_demo_flow.py",
    "scripts/build_product_release.py", "scripts/audit_release_artifact.py",
    "scripts/build_github_source.py", "scripts/audit_github_release.py",
    "README.md", "LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "PUBLIC_RELEASE_CHECKLIST.md", "CHANGELOG.md", "UPLOAD_TO_GITHUB_FROM_MAC.txt",
    ".env.example", ".gitignore", ".gitattributes", ".editorconfig",
    ".github/workflows/validate.yml", ".github/dependabot.yml",
]
GATES = [
    ("Product validation", [sys.executable, "validate_product.py"]),
    ("Safe startup", [sys.executable, "aria_safe_startup_check.py"]),
    ("ARIA v3 router", [sys.executable, "scripts/test_v3_router.py"]),
    ("ARIA v3 local reference knowledge", [sys.executable, "scripts/test_v3_reference_knowledge.py"]),
    ("ARIA v3 SOC conversation", [sys.executable, "scripts/test_v3_conversation.py"]),
    ("ARIA v3 evidence deliverables", [sys.executable, "scripts/test_v3_deliverables.py"]),
    ("ARIA v3 conference demo flow", [sys.executable, "scripts/test_v3_demo_flow.py"]),
    ("ARIA v3 SPL builder", [sys.executable, "scripts/test_v3_spl_builder.py"]),
    ("ARIA v3 investigation contract", [sys.executable, "scripts/test_v3_investigation_contract.py"]),
    ("ARIA v3 live evidence continuity", [sys.executable, "scripts/test_v3_live_evidence_continuity.py"]),
    ("ARIA v3 triage", [sys.executable, "scripts/test_v3_triage.py"]),
    ("ARIA v3 architecture", [sys.executable, "scripts/test_v3_architecture.py"]),
    ("ARIA v3 transactional deployment", [sys.executable, "scripts/test_v3_transactional_deployment.py"]),
    ("Investigation execution semantic unit", [sys.executable, "scripts/test_copilot_semantic_unit.py"]),
    ("Investigation execution semantic guards", [sys.executable, "scripts/test_copilot_semantic_guards.py"]),
    ("Catalog precedence", [sys.executable, "scripts/test_exact_catalog_precedence.py"]),
    ("Observed-schema binding", [sys.executable, "scripts/test_semantic_field_binding.py"]),
    ("SPL safety validator", [sys.executable, "scripts/test_spl_validator_unit.py"]),
    ("Product hardcoding audit", [sys.executable, "scripts/audit_no_product_hardcoding.py"]),
    ("Silent safety failure audit", [sys.executable, "scripts/audit_no_silent_safety_failures.py"]),
    ("Console warning audit", [sys.executable, "scripts/audit_no_console_warning_spam.py"]),
    ("Analyst workspace UI", [sys.executable, "scripts/test_analyst_workspace_ui.py"]),
    ("Chat progress UI", [sys.executable, "scripts/test_chat_ui_progress.py"]),
    ("Scroll shell UI", [sys.executable, "scripts/test_ui_scroll_shell.py"]),
    ("Build release artifacts", [sys.executable, "scripts/build_product_release.py"]),
    ("Release artifact audit", [sys.executable, "scripts/audit_release_artifact.py"]),
    ("Build GitHub source bundle", [sys.executable, "scripts/build_github_source.py"]),
    ("GitHub publication audit", [sys.executable, "scripts/audit_github_release.py"]),
]


def run_gate(name: str, command: list[str]) -> bool:
    print(f"\n{name}\n{'-' * len(name)}")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    print(f"{'PASS' if result.returncode == 0 else 'FAIL'}   {name}")
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ARIA v3 final product acceptance.")
    parser.add_argument("--skip-live", action="store_true", help="Run package gates without requiring the connected live acceptance report.")
    args = parser.parse_args()

    print("ARIA v3.0 Final Architecture Acceptance")
    print("=======================================")
    failures = 0
    version = (ROOT / "product" / "VERSION").read_text(encoding="utf-8").strip()
    if not version.startswith("3."):
        print(f"FAIL   unsupported version {version}")
        failures += 1
    for relative in REQUIRED_FILES:
        path = ROOT / relative
        if not path.exists() or path.stat().st_size == 0:
            print(f"FAIL   missing {relative}")
            failures += 1
    for name, command in GATES:
        if not run_gate(name, command):
            failures += 1

    if not args.skip_live:
        report_path = ROOT / "data" / "test_results" / "live_v3_acceptance.json"
        print("\nConnected live acceptance\n-------------------------")
        if not report_path.exists():
            print(f"FAIL   missing {report_path}")
            failures += 1
        else:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("version") != version or report.get("status") != "PASS":
                print(f"FAIL   live acceptance status={report.get('status')} version={report.get('version')}")
                failures += 1
            else:
                print("PASS   ARIA_V3_LIVE_ACCEPTANCE=PASS")

    print(f"\nFailures: {failures}")
    marker = "PASS" if failures == 0 else "FAIL"
    print(f"ARIA_V3_FINAL_ACCEPTANCE_STATUS={marker}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
