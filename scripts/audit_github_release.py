from __future__ import annotations

import json
import re
import tarfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
VERSION = (PROJECT / "product" / "VERSION").read_text(encoding="utf-8").strip()
ARCHIVE_ROOT = f"aria-v{VERSION}"
ARCHIVE = PROJECT / "releases" / f"{ARCHIVE_ROOT}-github-source.tar.gz"

REQUIRED = {
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    ".github/workflows/validate.yml",
    ".github/dependabot.yml",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "PUBLIC_RELEASE_CHECKLIST.md",
    "README.md",
    "SECURITY.md",
    "UPLOAD_TO_GITHUB_FROM_MAC.txt",
    "docs/ARCHITECTURE.md",
    "docs/PATTERN_COMPARISON.md",
    "docs/SEC1436_THREE_PATTERN_ARCHITECTURE.md",
    "docs/SEC1436_DEMO_RUNBOOK.md",
    "docs/CONFIGURATION.md",
    "docs/GITHUB_UI_PUBLISHING.md",
    "docs/INSTALLATION.md",
    "docs/RC11_DEMO_PROMPTS.txt",
    "docs/REPOSITORY_CONTENTS.md",
    "docs/TROUBLESHOOTING.md",
    "patterns/README.md",
    "patterns/pattern-a-ai-toolkit/README.md",
    "patterns/pattern-a-ai-toolkit/INSTALLATION.md",
    "patterns/pattern-a-ai-toolkit/USE_CASES.md",
    "patterns/pattern-a-ai-toolkit/SECURITY_AND_VALIDATION.md",
    "patterns/pattern-a-ai-toolkit/VALIDATION_REPORT.md",
    "patterns/pattern-a-ai-toolkit/examples/PORTABLE_SPL_TEMPLATES.md",
    "patterns/pattern-a-ai-toolkit/assets/01-event-to-mitre-assistance.png",
    "patterns/pattern-a-ai-toolkit/assets/02-coverage-gap-hypotheses.png",
    "patterns/pattern-a-ai-toolkit/assets/03-spl-optimisation-assistance.png",
    "patterns/pattern-a-ai-toolkit/assets/04-raw-to-tstats-assistance.png",
    "patterns/pattern-a-ai-toolkit/assets/05-json-to-cim-assistance.png",
    "patterns/pattern-c-dsdl-rag/README.md",
    "patterns/pattern-c-dsdl-rag/CAPABILITIES_TO_TRY_NEXT.md",
    "patterns/pattern-c-dsdl-rag/EXPERIMENT_BACKLOG.md",
    "patterns/pattern-c-dsdl-rag/SECURITY_AND_EVALUATION.md",
    "patterns/pattern-c-dsdl-rag/templates/corpus_manifest.example.yaml",
    "patterns/pattern-c-dsdl-rag/templates/evaluation_cases.example.jsonl",
    "patterns/pattern-c-dsdl-rag/templates/MODEL_CARD_TEMPLATE.md",
    "product/VERSION",
    "product/release_manifest.json",
    "product/knowledge/reference_cards.json",
    "aria/v3/reference_knowledge.py",
    "aria/v3/deliverable_agent.py",
    "aria/v3/conversation_agent.py",
    "scripts/test_v3_reference_knowledge.py",
    "scripts/test_v3_conversation.py",
    "scripts/test_v3_deliverables.py",
    "scripts/test_v3_demo_flow.py",
    "scripts/build_github_source.py",
    "scripts/audit_github_release.py",
}
FORBIDDEN_NAMES = [
    r"(^|/)\.env($|\.)",
    r"(^|/)\.git/",
    r"(^|/)\.venv/",
    r"(^|/)__pycache__/",
    r"(^|/)checkpoints/",
    r"(^|/)data/",
    r"(^|/)releases/",
    r"\.backup$",
    r"\.log$",
    r"\.pid$",
    r"\.py[co]$",
    r"\.(?:tar|tgz|gz|zip)$",
]
ENVIRONMENT_PATTERNS = {
    "private IPv4 address": r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})\b",
    "user home deployment path": r"/home/[^/\s\"']+/aria-pattern-b",
    "URL with embedded credentials": r"https?://[^\s/:]+:[^@\s/]+@",
}
SECRET_PATTERNS = {
    "private key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "AWS access key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub token": r"\bgh[opsu]_[A-Za-z0-9_]{30,}\b",
    "Slack token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "generic bearer token": r"(?i)\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/-]{20,}",
}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsonl",
    ".md",
    ".meta",
    ".py",
    ".sh",
    ".spec",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def read_text(archive: tarfile.TarFile, name: str) -> str:
    member = archive.getmember(name)
    handle = archive.extractfile(member)
    if handle is None:
        raise AssertionError(f"unable to read {name}")
    return handle.read().decode("utf-8", errors="replace")


def report_failure(failures: list[str], message: str) -> None:
    if message not in failures:
        failures.append(message)


def audit_env_example(text: str, failures: list[str]) -> None:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    for key in ("SPLUNK_USERNAME", "SPLUNK_PASSWORD"):
        if values.get(key):
            report_failure(failures, f".env.example contains a non-empty {key}")
    for key, value in values.items():
        if any(label in key.upper() for label in ("API_KEY", "SECRET", "TOKEN")) and value:
            report_failure(failures, f".env.example contains a non-empty sensitive value {key}")
    for key in ("SPLUNK_URL", "OLLAMA_URL"):
        value = values.get(key, "")
        if value and ".example.invalid" not in value:
            report_failure(failures, f".env.example {key} is not a reserved example.invalid endpoint")


def main() -> int:
    print("ARIA GitHub Source Release Audit")
    print("===============================")
    failures: list[str] = []
    if not ARCHIVE.exists():
        print(f"FAIL   missing {ARCHIVE}")
        print("ARIA_GITHUB_RELEASE_AUDIT=FAIL")
        return 1

    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        prefix = f"{ARCHIVE_ROOT}/"
        if any(not name.startswith(prefix) for name in names):
            report_failure(failures, "archive contains entries outside its versioned root")
        if any(not member.isfile() for member in members):
            report_failure(failures, "archive contains a non-regular entry")

        relative_names = {name[len(prefix):] for name in names if name.startswith(prefix)}
        for required in REQUIRED:
            if required not in relative_names:
                report_failure(failures, f"missing required public file {required}")

        for relative in sorted(relative_names):
            if relative == ".env.example":
                continue
            for pattern in FORBIDDEN_NAMES:
                if re.search(pattern, relative):
                    report_failure(failures, f"forbidden archive entry {relative}")

        version_name = f"{prefix}product/VERSION"
        if version_name in names and read_text(archive, version_name).strip() != VERSION:
            report_failure(failures, "packaged product version does not match archive version")

        manifest_name = f"{prefix}product/release_manifest.json"
        if manifest_name in names:
            manifest = json.loads(read_text(archive, manifest_name))
            if manifest.get("version") != VERSION:
                report_failure(failures, "release manifest version mismatch")
            capabilities = " ".join(manifest.get("capabilities") or []).lower()
            if "offline reference grounding" not in capabilities:
                report_failure(failures, "manifest omits offline reference grounding")
            if "github source bundle" not in capabilities:
                report_failure(failures, "manifest omits GitHub publication packaging")

        reference_name = f"{prefix}product/knowledge/reference_cards.json"
        if reference_name in names:
            reference_data = json.loads(read_text(archive, reference_name))
            cards = reference_data.get("cards") or []
            if not cards:
                report_failure(failures, "reference card catalogue is empty")
            for card in cards:
                if not card.get("required_phrases"):
                    report_failure(failures, f"reference card {card.get('id')} has no required phrases")
                sources = card.get("sources") or []
                if not sources or any(not str(source.get("url", "")).startswith("https://") for source in sources):
                    report_failure(failures, f"reference card {card.get('id')} lacks HTTPS source attribution")

        env_name = f"{prefix}.env.example"
        if env_name in names:
            audit_env_example(read_text(archive, env_name), failures)

        for member in members:
            relative = member.name[len(prefix):] if member.name.startswith(prefix) else member.name
            if Path(relative).suffix.lower() not in TEXT_SUFFIXES or member.size > 2_000_000:
                continue
            text = read_text(archive, member.name)
            for label, pattern in ENVIRONMENT_PATTERNS.items():
                if re.search(pattern, text):
                    report_failure(failures, f"{label} found in {relative}")
            for label, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, text):
                    report_failure(failures, f"{label} found in {relative}")

    if failures:
        for failure in failures:
            print(f"FAIL   {failure}")
        print("ARIA_GITHUB_RELEASE_AUDIT=FAIL")
        return 1

    print(f"PASS   {ARCHIVE.name}")
    print("PASS   required public documentation and licence present")
    print("PASS   no runtime data, local environment or nested release artifact")
    print("PASS   no recognised secret or environment-specific value")
    print("PASS   public framework cards retain HTTPS source attribution")
    print("ARIA_GITHUB_RELEASE_AUDIT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
