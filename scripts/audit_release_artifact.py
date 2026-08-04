from __future__ import annotations

import json
import re
import tarfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
VERSION = (PROJECT / "product" / "VERSION").read_text(encoding="utf-8").strip()
CONTROLLED = PROJECT / "releases" / f"aria-v{VERSION}.tar"
REPLICATION = PROJECT / "releases" / f"aria-sec1436-replication-kit-v{VERSION}.tar"
FORBIDDEN = [
    r"(^|/)\.venv/", r"(^|/)data/", r"(^|/)checkpoints/",
    r"(^|/)releases/", r"(^|/)__pycache__/", r"\.pyc$", r"\.log$", r"\.pid$", r"\.backup",
]
REQUIRED = [
    "aria-pattern-b/product/VERSION",
    "aria-pattern-b/product/release_manifest.json",
    "aria-pattern-b/product/safety_policy.json",
    "aria-pattern-b/product/evidence_policy.json",
    "aria-pattern-b/aria/copilot/engine.py",
    "aria-pattern-b/aria/v3/orchestrator.py",
    "aria-pattern-b/aria/v3/router.py",
    "aria-pattern-b/aria/v3/telemetry_intelligence.py",
    "aria-pattern-b/aria/v3/conversation_agent.py",
    "aria-pattern-b/aria/v3/reference_knowledge.py",
    "aria-pattern-b/aria/v3/deliverable_agent.py",
    "aria-pattern-b/aria/v3/spl_builder_agent.py",
    "aria-pattern-b/aria/v3/investigation_agent.py",
    "aria-pattern-b/aria/v3/triage_agent.py",
    "aria-pattern-b/aria/spl_validator.py",
    "aria-pattern-b/web_ui.py",
    "aria-pattern-b/scripts/deploy_v3_release.py",
    "aria-pattern-b/scripts/live_v3_acceptance.py",
    "aria-pattern-b/scripts/test_v3_router.py",
    "aria-pattern-b/scripts/test_v3_conversation.py",
    "aria-pattern-b/scripts/test_v3_reference_knowledge.py",
    "aria-pattern-b/scripts/test_v3_deliverables.py",
    "aria-pattern-b/scripts/test_v3_demo_flow.py",
    "aria-pattern-b/scripts/test_v3_spl_builder.py",
    "aria-pattern-b/scripts/test_v3_investigation_contract.py",
    "aria-pattern-b/scripts/test_v3_live_evidence_continuity.py",
    "aria-pattern-b/scripts/test_v3_triage.py",
    "aria-pattern-b/scripts/test_v3_architecture.py",
    "aria-pattern-b/docs/V3_ARCHITECTURE.md",
    "aria-pattern-b/docs/V3_RELEASE_NOTES.md",
    "aria-pattern-b/product/knowledge/reference_cards.json",
    "aria-pattern-b/README.md",
    "aria-pattern-b/LICENSE",
    "aria-pattern-b/NOTICE",
    "aria-pattern-b/SECURITY.md",
    "aria-pattern-b/PUBLIC_RELEASE_CHECKLIST.md",
    "aria-pattern-b/docs/DEMO_GUIDE.md",
    "aria-pattern-b/scripts/build_github_source.py",
    "aria-pattern-b/scripts/audit_github_release.py",
]


def read(tar: tarfile.TarFile, name: str) -> str:
    handle = tar.extractfile(tar.getmember(name))
    if handle is None:
        raise AssertionError(name)
    return handle.read().decode("utf-8", errors="replace")


def audit(path: Path, *, require_splunk_app: bool = False) -> list[str]:
    failures: list[str] = []
    if not path.exists():
        return [f"missing archive: {path}"]
    with tarfile.open(path, "r:*") as tar:
        names = tar.getnames()
        for name in names:
            if re.search(r"(^|/)\.env($|\.)", name) and not name.endswith("/.env.example"):
                failures.append(f"{path.name}: forbidden entry {name}")
            for pattern in FORBIDDEN:
                if re.search(pattern, name):
                    failures.append(f"{path.name}: forbidden entry {name}")
        for required in REQUIRED:
            if required not in names:
                failures.append(f"{path.name}: missing {required}")
        if require_splunk_app and not any(name.startswith("aria_local_llm/") for name in names):
            failures.append(f"{path.name}: no Splunk-side aria_local_llm app content")
        packaged = read(tar, "aria-pattern-b/product/VERSION").strip() if "aria-pattern-b/product/VERSION" in names else ""
        if packaged != VERSION:
            failures.append(f"{path.name}: packaged version {packaged!r} != {VERSION!r}")
        manifest_name = "aria-pattern-b/product/release_manifest.json"
        if manifest_name in names:
            manifest = json.loads(read(tar, manifest_name))
            if manifest.get("version") != VERSION:
                failures.append(f"{path.name}: manifest version mismatch")
            capabilities = " ".join(manifest.get("capabilities") or []).lower()
            for capability in ("conversation agent", "spl builder agent", "investigation agent", "triage agent", "telemetry intelligence"):
                if capability not in capabilities:
                    failures.append(f"{path.name}: manifest missing {capability}")
        router_name = "aria-pattern-b/aria/v3/router.py"
        if router_name in names:
            router = read(tar, router_name)
            if "structured_chat" in router or ".chat(" in router:
                failures.append(f"{path.name}: generative dependency found in v3 router")
        deployer_name = "aria-pattern-b/scripts/deploy_v3_release.py"
        if deployer_name in names:
            deployer = read(tar, deployer_name)
            if deployer.find("compile_source(source, python)") > deployer.find("copy_release(source, target)"):
                failures.append(f"{path.name}: runtime can be modified before source compile preflight")
            if "restore_runtime(target, backup)" not in deployer:
                failures.append(f"{path.name}: transactional rollback missing")
        for name in names:
            if not name.endswith((".py", ".sh", ".md", ".txt", ".json", ".conf", ".ini", ".cfg", ".meta")):
                continue
            text = read(tar, name)
            if re.search(r"/home/[^/\s]+/aria-pattern-b", text) or re.search(r"\b10\.66\.212\.\d+\b", text):
                failures.append(f"{path.name}: environment-specific value in {name}")
    return failures


def main() -> int:
    print("ARIA v3 Release Artifact Audit")
    print("==============================")
    failures: list[str] = []
    current = audit(CONTROLLED)
    if current:
        failures.extend(current)
    else:
        print(f"PASS   {CONTROLLED.name}")
    if REPLICATION.exists():
        current = audit(REPLICATION, require_splunk_app=True)
        if current:
            failures.extend(current)
        else:
            print(f"PASS   {REPLICATION.name}")
            print("ARIA_SEC1436_REPLICATION_KIT_AUDIT=PASS")
    else:
        print(f"SKIP   {REPLICATION.name} - not built because Splunk-side app source is unavailable")
        print("ARIA_SEC1436_REPLICATION_KIT_AUDIT=NOT_RUN")
    if failures:
        for item in failures:
            print(f"FAIL   {item}")
        print("ARIA_RELEASE_ARTIFACT_AUDIT=FAIL")
        return 1
    print("ARIA_RELEASE_ARTIFACT_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
