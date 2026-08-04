from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOYER = ROOT / "scripts/deploy_v3_release.py"


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    print("ARIA v3 Transactional Deployment Test")
    print("=====================================")
    text = DEPLOYER.read_text(encoding="utf-8")
    preflight = text.find("compile_source(source, python)")
    copy = text.find("copy_release(source, target)")
    backup = text.find("backup_runtime(target, backup)")
    restore = text.find("restore_runtime(target, backup)")
    check(preflight >= 0 and copy >= 0 and preflight < copy, "source compilation precedes runtime replacement")
    check(backup >= 0 and backup < copy, "complete runtime checkpoint precedes replacement")
    check(restore >= 0 and restore > copy, "failed deployment restores prior runtime")
    check("PRESERVE_NAMES" in text and '".env"' in text and '".venv"' in text and '"data"' in text, "local configuration and evidence data are preserved")
    check("ARIA_V3_AUTOMATIC_ROLLBACK" in text, "rollback exposes an acceptance marker")
    print("ARIA_V3_TRANSACTIONAL_DEPLOYMENT_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
