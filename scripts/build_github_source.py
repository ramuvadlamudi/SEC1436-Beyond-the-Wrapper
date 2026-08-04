from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
RELEASES = PROJECT / "releases"
VERSION = (PROJECT / "product" / "VERSION").read_text(encoding="utf-8").strip()
ARCHIVE_ROOT = f"aria-v{VERSION}"
OUTPUT = RELEASES / f"{ARCHIVE_ROOT}-github-source.tar.gz"

ROOT_FILES = {
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "PUBLIC_RELEASE_CHECKLIST.md",
    "README.md",
    "README_ARIA_OPERATOR_GUIDE.md",
    "SECURITY.md",
    "SECURITY_MODEL.md",
    "UPLOAD_TO_GITHUB_FROM_MAC.txt",
    "aria_health.py",
    "aria_llm_gateway.py",
    "aria_safe_startup_check.py",
    "main.py",
    "requirements.txt",
    "validate_product.py",
    "validate_runtime.py",
    "validate_v1_acceptance.py",
    "validate_v3_acceptance.py",
    "web_ui.py",
}
SOURCE_DIRS = {".github", "aria", "docs", "patterns", "product", "scripts"}
FORBIDDEN_PARTS = {
    ".git",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    ".vscode",
    "__pycache__",
    "checkpoints",
    "data",
    "releases",
    "venv",
}
FORBIDDEN_SUFFIXES = {".backup", ".log", ".pid", ".pyc", ".pyo"}


def included(path: Path) -> bool:
    relative = path.relative_to(PROJECT)
    if any(part in FORBIDDEN_PARTS for part in relative.parts):
        return False
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return False
    if path.name.startswith(".env") and path.name != ".env.example":
        return False
    if len(relative.parts) == 1:
        return path.name in ROOT_FILES
    if relative.parts[0] == ".github":
        return not any(part.startswith(".") for part in relative.parts[1:])
    return relative.parts[0] in SOURCE_DIRS and not any(part.startswith(".") for part in relative.parts)


def normalised_info(path: Path, arcname: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(arcname)
    info.size = size
    info.mode = 0o755 if path.suffix == ".sh" else 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def sha256(path: Path) -> Path:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    checksum = Path(str(path) + ".sha256")
    checksum.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return checksum


def main() -> int:
    RELEASES.mkdir(parents=True, exist_ok=True)
    OUTPUT.unlink(missing_ok=True)
    Path(str(OUTPUT) + ".sha256").unlink(missing_ok=True)

    paths = [path for path in sorted(PROJECT.rglob("*")) if path.is_file() and included(path)]
    with OUTPUT.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in paths:
                    payload = path.read_bytes()
                    relative = path.relative_to(PROJECT).as_posix()
                    info = normalised_info(path, f"{ARCHIVE_ROOT}/{relative}", len(payload))
                    archive.addfile(info, io.BytesIO(payload))

    checksum = sha256(OUTPUT)
    print(f"GITHUB_SOURCE={OUTPUT}")
    print(f"GITHUB_SOURCE_SHA256={checksum}")
    print(f"GITHUB_SOURCE_FILES={len(paths)}")
    print("ARIA_GITHUB_SOURCE_BUILD=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
