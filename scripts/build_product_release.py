from __future__ import annotations

import hashlib
import io
import re
import tarfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parent
SPLUNK_APP = ROOT / "aria_local_llm"
RELEASES = PROJECT / "releases"
VERSION = (PROJECT / "product" / "VERSION").read_text(encoding="utf-8").strip()
CONTROLLED = RELEASES / f"aria-v{VERSION}.tar"
REPLICATION = RELEASES / f"aria-sec1436-replication-kit-v{VERSION}.tar"
ROOT_FILES = {
    "requirements.txt", "web_ui.py", "main.py", "aria_llm_gateway.py",
    "validate_product.py", "validate_runtime.py", "validate_v1_acceptance.py", "validate_v3_acceptance.py",
    "aria_safe_startup_check.py", "aria_health.py", "README_ARIA_OPERATOR_GUIDE.md", "SECURITY_MODEL.md",
    ".env.example", ".gitignore", "README.md", "LICENSE", "NOTICE", "SECURITY.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "PUBLIC_RELEASE_CHECKLIST.md",
}
TEXT_SUFFIXES = {".py", ".json", ".conf", ".md", ".txt", ".sh", ".html", ".js", ".css", ".xml", ".ini", ".cfg", ".spec", ".meta"}


def safe_file(path: Path, base: Path) -> bool:
    parts = path.relative_to(base).parts
    if path.name.startswith(".env") and path.name != ".env.example":
        return False
    if path.suffix in {".pyc", ".log", ".pid"}:
        return False
    return not any(part in {"__pycache__", ".venv", "data", "checkpoints", "releases"} for part in parts)


def include_project(path: Path) -> bool:
    rel = path.relative_to(PROJECT).as_posix()
    return (
        rel in ROOT_FILES
        or rel.startswith("aria/")
        or rel.startswith("product/")
        or rel.startswith("docs/")
        or rel.startswith("scripts/")
    )


def sanitise(text: str) -> str:
    text = re.sub(r"\b(https?://)(?:\d{1,3}\.){3}\d{1,3}(:\d+)?\b", lambda match: f"{match.group(1)}127.0.0.1{match.group(2) or ''}", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "127.0.0.1", text)
    text = re.sub(r"/home/[^/\s\"']+/aria-pattern-b", "/opt/aria-pattern-b", text)
    return text


def add_bytes(tar: tarfile.TarFile, source: Path, arcname: str, payload: bytes) -> None:
    info = tar.gettarinfo(str(source), arcname=arcname)
    info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))


def add_project(tar: tarfile.TarFile) -> None:
    for path in sorted(PROJECT.rglob("*")):
        if path.is_file() and safe_file(path, PROJECT) and include_project(path):
            tar.add(path, arcname=f"aria-pattern-b/{path.relative_to(PROJECT)}", recursive=False)


def splunk_app_files() -> list[Path]:
    if not SPLUNK_APP.exists():
        return []
    return [
        path
        for path in sorted(SPLUNK_APP.rglob("*"))
        if path.is_file() and safe_file(path, SPLUNK_APP)
    ]


def add_splunk_app(tar: tarfile.TarFile, paths: list[Path]) -> None:
    for path in paths:
        arcname = f"aria_local_llm/{path.relative_to(SPLUNK_APP)}"
        if path.suffix.lower() in TEXT_SUFFIXES:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                tar.add(path, arcname=arcname, recursive=False)
            else:
                add_bytes(tar, path, arcname, sanitise(text).encode("utf-8"))
        else:
            tar.add(path, arcname=arcname, recursive=False)


def sha256(path: Path) -> Path:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    output = Path(str(path) + ".sha256")
    output.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return output


def build(path: Path, *, app_paths: list[Path] | None = None) -> None:
    path.unlink(missing_ok=True)
    Path(str(path) + ".sha256").unlink(missing_ok=True)
    with tarfile.open(path, "w") as tar:
        add_project(tar)
        if app_paths:
            add_splunk_app(tar, app_paths)
    print(f"BUILT {path}")
    print(f"SHA   {sha256(path)}")


def main() -> int:
    RELEASES.mkdir(parents=True, exist_ok=True)
    build(CONTROLLED)
    print(f"CONTROLLED_RELEASE={CONTROLLED}")
    app_paths = splunk_app_files()
    if app_paths:
        build(REPLICATION, app_paths=app_paths)
        print(f"CUSTOMER_REPLICATION_KIT={REPLICATION}")
        print("ARIA_SEC1436_REPLICATION_KIT_BUILD=PASS")
    else:
        REPLICATION.unlink(missing_ok=True)
        Path(str(REPLICATION) + ".sha256").unlink(missing_ok=True)
        print(f"SKIP  SEC1436 replication kit: no files found under {SPLUNK_APP}")
        print("ARIA_SEC1436_REPLICATION_KIT_BUILD=NOT_BUILT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
