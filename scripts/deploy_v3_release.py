from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


PRESERVE_NAMES = {".env", ".venv", "data", "releases", "checkpoints"}
RUNTIME_PATHS = (
    "aria", "web_ui.py", "main.py", "aria_llm_gateway.py", "product", "docs", "scripts",
    "validate_product.py", "validate_runtime.py", "validate_v1_acceptance.py", "validate_v3_acceptance.py",
    "aria_safe_startup_check.py", "aria_health.py", "README_ARIA_OPERATOR_GUIDE.md",
    "README.md", "SECURITY.md", "SECURITY_MODEL.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "PUBLIC_RELEASE_CHECKLIST.md", "LICENSE", "NOTICE",
    ".env.example", ".gitignore", "requirements.txt",
)


def safe_extract(archive: Path, target: Path) -> None:
    root = target.resolve()
    with tarfile.open(archive, "r:*") as handle:
        for member in handle.getmembers():
            destination = (target / member.name).resolve()
            if destination != root and root not in destination.parents:
                raise RuntimeError(f"Unsafe archive member path: {member.name}")
        try:
            handle.extractall(target, filter="data")
        except TypeError:
            handle.extractall(target)


def source_from_archive(archive: Path, target: Path) -> Path:
    safe_extract(archive, target)
    source = target / "aria-pattern-b"
    if not source.exists():
        raise RuntimeError("Archive does not contain aria-pattern-b/")
    return source


def copy_path(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def backup_runtime(target: Path, backup: Path) -> None:
    for relative in RUNTIME_PATHS:
        current = target / relative
        if current.exists():
            copy_path(current, backup / relative)


def restore_runtime(target: Path, backup: Path) -> None:
    for relative in RUNTIME_PATHS:
        current = target / relative
        if current.is_dir():
            shutil.rmtree(current, ignore_errors=True)
        elif current.exists():
            current.unlink(missing_ok=True)
    for relative in RUNTIME_PATHS:
        saved = backup / relative
        if saved.exists():
            copy_path(saved, target / relative)


def copy_release(source: Path, target: Path) -> None:
    for item in source.iterdir():
        if item.name in PRESERVE_NAMES:
            continue
        destination = target / item.name
        if destination.is_dir():
            shutil.rmtree(destination, ignore_errors=True)
        elif destination.exists():
            destination.unlink(missing_ok=True)
        copy_path(item, destination)
    for cache in target.rglob("__pycache__"):
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
    for compiled in target.rglob("*.pyc"):
        compiled.unlink(missing_ok=True)


def runtime_env(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    prior = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(root) + (os.pathsep + prior if prior else "")
    return env


def compile_source(source: Path, python: Path) -> None:
    command = [
        str(python), "-m", "compileall", "-q",
        "aria", "scripts", "web_ui.py", "main.py", "aria_llm_gateway.py",
        "validate_product.py", "validate_runtime.py", "validate_v3_acceptance.py",
    ]
    print("PREFLIGHT", " ".join(command))
    subprocess.run(command, cwd=source, env=runtime_env(source), check=True)
    print("ARIA_V3_SOURCE_COMPILE_PREFLIGHT=PASS")


def run_checks(target: Path, python: Path) -> None:
    env = runtime_env(target)
    checks = [
        [str(python), "scripts/test_v3_router.py"],
        [str(python), "scripts/test_v3_reference_knowledge.py"],
        [str(python), "scripts/test_v3_conversation.py"],
        [str(python), "scripts/test_v3_deliverables.py"],
        [str(python), "scripts/test_v3_demo_flow.py"],
        [str(python), "scripts/test_v3_spl_builder.py"],
        [str(python), "scripts/test_v3_investigation_contract.py"],
        [str(python), "scripts/test_v3_live_evidence_continuity.py"],
        [str(python), "scripts/test_v3_triage.py"],
        [str(python), "scripts/test_v3_architecture.py"],
        [str(python), "scripts/test_v3_transactional_deployment.py"],
        [str(python), "scripts/test_copilot_semantic_unit.py"],
        [str(python), "scripts/test_copilot_semantic_guards.py"],
        [str(python), "scripts/test_exact_catalog_precedence.py"],
        [str(python), "scripts/test_semantic_field_binding.py"],
        [str(python), "scripts/test_spl_validator_unit.py"],
        [str(python), "scripts/audit_no_product_hardcoding.py"],
        [str(python), "scripts/audit_no_silent_safety_failures.py"],
        [str(python), "scripts/audit_no_console_warning_spam.py"],
        [str(python), "scripts/test_analyst_workspace_ui.py"],
        [str(python), "scripts/test_chat_ui_progress.py"],
        [str(python), "scripts/test_ui_scroll_shell.py"],
    ]
    for command in checks:
        print("RUN", " ".join(command))
        subprocess.run(command, cwd=target, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Transactionally deploy the ARIA v3 multi-agent SOC copilot.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--archive", type=Path)
    source_group.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    target = args.target.expanduser().resolve()
    if not (target / ".env").exists():
        raise RuntimeError(f"Target does not contain .env: {target}")
    python = target / ".venv" / "bin" / "python"
    if not python.exists():
        python = Path(sys.executable)

    with tempfile.TemporaryDirectory(prefix="aria-v3-deploy-") as temporary:
        temp = Path(temporary)
        source = source_from_archive(args.archive.expanduser().resolve(), temp) if args.archive else args.source.expanduser().resolve()
        version = (source / "product" / "VERSION").read_text(encoding="utf-8").strip()
        if not version.startswith("3."):
            raise RuntimeError(f"Source is not an ARIA v3 release: {version}")
        required = [
            source / "aria" / "v3" / "router.py",
            source / "aria" / "v3" / "conversation_agent.py",
            source / "aria" / "v3" / "reference_knowledge.py",
            source / "aria" / "v3" / "deliverable_agent.py",
            source / "aria" / "v3" / "orchestrator.py",
            source / "aria" / "v3" / "spl_builder_agent.py",
            source / "aria" / "v3" / "investigation_agent.py",
            source / "aria" / "v3" / "triage_agent.py",
            source / "aria" / "v3" / "telemetry_intelligence.py",
            source / "product" / "knowledge" / "reference_cards.json",
        ]
        if not all(path.exists() for path in required):
            raise RuntimeError("Source is missing one or more ARIA v3 agents")

        compile_source(source, python)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = target / "checkpoints" / f"before-v{version}-{stamp}"
        backup.mkdir(parents=True, exist_ok=True)
        backup_runtime(target, backup)
        try:
            copy_release(source, target)
            run_checks(target, python)
        except BaseException:
            print("DEPLOYMENT_CHECK_FAILED=YES")
            print(f"ROLLBACK_SOURCE={backup}")
            restore_runtime(target, backup)
            restored = subprocess.run(
                [str(python), "-m", "compileall", "-q", "aria", "web_ui.py", "main.py", "aria_llm_gateway.py"],
                cwd=target,
                env=runtime_env(target),
                check=False,
            )
            print(f"ARIA_V3_AUTOMATIC_ROLLBACK={'PASS' if restored.returncode == 0 else 'FAILED'}")
            raise

    if not args.no_restart:
        for service in ("aria-llm-gateway", "aria-web"):
            subprocess.run(["sudo", "systemctl", "restart", service], check=True)
            subprocess.run(["systemctl", "is-active", "--quiet", service], check=True)

    print()
    print(f"ARIA v3 transactional deployment completed: {target}")
    print(f"Backup created: {backup}")
    if args.no_restart:
        print("RESTART_REQUIRED=sudo systemctl restart aria-llm-gateway aria-web")
    print("NEXT_GATE=python scripts/live_v3_acceptance.py --help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
