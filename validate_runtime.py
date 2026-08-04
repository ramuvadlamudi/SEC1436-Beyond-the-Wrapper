from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def load_env(path: str = ".env") -> dict[str, str]:
    values: dict[str, str] = {}
    source = Path(path)
    if not source.exists():
        return values
    for line in source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def ssl_context(url: str, verify_ssl: bool) -> ssl.SSLContext | None:
    if url.startswith("https://") and not verify_ssl:
        return ssl._create_unverified_context()
    return None


def get_json(url: str, *, timeout: int = 15, verify_ssl: bool = True) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(
        request,
        timeout=timeout,
        context=ssl_context(url, verify_ssl),
    ) as response:
        body = response.read().decode("utf-8", errors="replace")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError("Endpoint returned a non-object JSON response")
    return parsed


def splunk_search(env: dict[str, str], spl: str, timeout: int = 30) -> str:
    base_url = env.get("SPLUNK_URL", "").rstrip("/")
    username = env.get("SPLUNK_USERNAME", "")
    password = env.get("SPLUNK_PASSWORD", "")
    verify_ssl = env.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"
    if not base_url or not username or not password:
        raise RuntimeError("Missing SPLUNK_URL, SPLUNK_USERNAME or SPLUNK_PASSWORD")

    data = urllib.parse.urlencode(
        {"search": spl, "output_mode": "json", "exec_mode": "oneshot"}
    ).encode("utf-8")
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        base_url + "/services/search/jobs",
        data=data,
        method="POST",
        headers={
            "Authorization": "Basic " + auth,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(
        request,
        timeout=timeout,
        context=ssl_context(base_url, verify_ssl),
    ) as response:
        return response.read().decode("utf-8", errors="replace")


def test_splunk(env: dict[str, str]) -> tuple[bool, str]:
    try:
        body = splunk_search(
            env,
            '| makeresults | eval status="ARIA_SPLUNK_CONNECTIVITY_OK" | table status',
            timeout=30,
        )
        if "ARIA_SPLUNK_CONNECTIVITY_OK" not in body:
            return False, "Splunk responded but the read-only connectivity marker was absent"
        return True, "Read-only SPL connectivity test passed"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def test_splunk_live_catalog(env: dict[str, str]) -> tuple[bool, str]:
    try:
        body = splunk_search(
            env,
            "| tstats count as event_count where index=* by index sourcetype | head 1",
            timeout=45,
        )
        if "event_count" not in body and "sourcetype" not in body:
            return False, "Splunk returned no live catalog fields"
        return True, "Live index/sourcetype catalog query passed"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def normalise_model_name(value: str) -> str:
    value = str(value or "").strip()
    return value[:-7] if value.endswith(":latest") else value


def test_ollama_models(env: dict[str, str]) -> tuple[bool, str]:
    base_url = env.get("OLLAMA_URL", "").rstrip("/")
    configured = [
        env.get("OLLAMA_FAST_MODEL", ""),
        env.get("OLLAMA_REASONING_MODEL", ""),
        env.get("OLLAMA_EMBEDDING_MODEL", ""),
    ]
    if not base_url or not all(configured):
        return False, "Missing Ollama URL or configured model role"
    try:
        body = get_json(base_url + "/api/tags", timeout=20)
        installed = {
            normalise_model_name(str(item.get("name") or item.get("model") or ""))
            for item in body.get("models", [])
            if isinstance(item, dict)
        }
        missing = [name for name in configured if normalise_model_name(name) not in installed]
        if missing:
            return False, "Configured model(s) not installed: " + ", ".join(missing)
        return True, "Configured fast, reasoning and embedding models are installed"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def test_gateway(env: dict[str, str]) -> tuple[bool, str]:
    port = env.get("ARIA_LLM_GATEWAY_PORT", "8502")
    try:
        body = get_json(f"http://127.0.0.1:{port}/health", timeout=15)
        if not body:
            return False, "Gateway health response was empty"
        return True, "ARIA local LLM gateway reachable"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def status_line(status: str, name: str, detail: str) -> None:
    print(f"{status:<6} {name:<28} {detail}")


def main() -> int:
    env = load_env()
    version = Path("product/VERSION").read_text(encoding="utf-8").strip() if Path("product/VERSION").exists() else "unknown"
    print(f"ARIA {version} Runtime Validation")
    print("=" * (len(version) + 24))
    print()
    failures = 0
    warnings = 0

    checks = [
        ("Splunk REST", test_splunk),
        ("Splunk live catalog", test_splunk_live_catalog),
        ("Ollama models", test_ollama_models),
        ("ARIA LLM Gateway", test_gateway),
    ]
    for name, function in checks:
        passed, detail = function(env)
        status_line("PASS" if passed else "FAIL", name, detail)
        if not passed:
            failures += 1

    required_policies = [
        Path("product/safety_policy.json"),
        Path("product/evidence_policy.json"),
        Path("product/risk_policy.json"),
    ]
    if all(path.exists() and path.stat().st_size > 0 for path in required_policies):
        status_line("PASS", "Runtime policies", "safety, evidence and risk policies present")
    else:
        status_line("FAIL", "Runtime policies", "one or more policy files are missing")
        failures += 1

    audit_dir = Path(os.getenv("ARIA_AUDIT_DIR", "data/audit"))
    if audit_dir.exists():
        status_line("PASS", "Audit directory", str(audit_dir))
    else:
        status_line("WARN", "Audit directory", f"{audit_dir} does not exist yet")
        warnings += 1

    print()
    print("Summary")
    print("-------")
    print(f"Failures: {failures}")
    print(f"Warnings: {warnings}")
    if failures:
        print("\nARIA_RUNTIME_VALIDATION_STATUS=FAIL")
        return 1
    print("\nARIA_RUNTIME_VALIDATION_STATUS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
