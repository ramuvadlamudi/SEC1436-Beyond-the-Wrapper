from __future__ import annotations
from aria.suppressed_exception_logger import log_suppressed_exception as _aria_log_suppressed_exception

import json
import os
import re
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
ENV_PATH = PROJECT_ROOT / ".env"


def load_dotenv() -> None:
    if not ENV_PATH.exists():
        return

    for line in ENV_PATH.read_text(errors="ignore").splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        os.environ.setdefault(key, value)


load_dotenv()


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


OLLAMA_URL = env("OLLAMA_URL").rstrip("/")
FAST_MODEL = env("OLLAMA_FAST_MODEL", env("OLLAMA_CODER_MODEL"))
CODER_MODEL = env("OLLAMA_CODER_MODEL", FAST_MODEL)
REASONING_MODEL = env("OLLAMA_REASONING_MODEL", FAST_MODEL)

if not OLLAMA_URL:
    raise RuntimeError("OLLAMA_URL must be configured in .env")
if not FAST_MODEL:
    raise RuntimeError("OLLAMA_FAST_MODEL must be configured in .env")
HOST = env("ARIA_LLM_GATEWAY_HOST", "0.0.0.0")
PORT = int(env("ARIA_LLM_GATEWAY_PORT", "8502"))
TIMEOUT = int(env("OLLAMA_GATEWAY_TIMEOUT", "180"))
KEEP_ALIVE = env("OLLAMA_GATEWAY_KEEP_ALIVE", "30m")


FAST_ROLES = {
    "",
    "default",
    "fast",
    "triage",
    "summary",
    "summarise",
    "summarize",
    "soc",
    "soc_review",
    "security",
    "security_review",
    "spl",
    "spl_review",
    "explain",
    "explanation",
}

REASONING_ROLES = {
    "reasoning",
    "deep",
    "deep_reasoning",
    "analysis",
    "architecture",
}


def choose_model(payload: dict[str, Any]) -> str:
    role = str(payload.get("model_role") or payload.get("role") or "triage").strip().lower()
    explicit_model = str(payload.get("model") or "").strip()

    if role in REASONING_ROLES:
        return REASONING_MODEL

    if role in FAST_ROLES:
        return FAST_MODEL

    if explicit_model in {"reasoning", "reasoning_model", "deep"}:
        return REASONING_MODEL

    if explicit_model in {"fast", "coder", "triage", "summary"}:
        return FAST_MODEL

    # Pattern A default: fast model for reliability.
    return FAST_MODEL


def compact_rows(rows: Any, limit: int = 20) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        return []

    compacted: list[dict[str, Any]] = []

    for row in rows[:limit]:
        if isinstance(row, dict):
            compacted.append({str(k): v for k, v in row.items() if v is not None})
        else:
            compacted.append({"value": str(row)})

    return compacted


def extract_json_object(text: str) -> dict[str, Any]:
    raw = str(text or "").strip()

    if not raw:
        return {}

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except Exception as _aria_suppressed_exception:
        _aria_log_suppressed_exception(_aria_suppressed_exception, component=__name__)

    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)

    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except Exception as _aria_suppressed_exception:
            _aria_log_suppressed_exception(_aria_suppressed_exception, component=__name__)

    return {}


def normalise_result(parsed: dict[str, Any], raw: str, model: str, latency_ms: int) -> dict[str, Any]:
    verdict = parsed.get("verdict") or parsed.get("status") or "INFO"
    confidence = parsed.get("confidence") or parsed.get("score") or "0"
    reasoning = parsed.get("reasoning") or parsed.get("summary") or parsed.get("analysis") or raw
    next_action = parsed.get("next_action") or parsed.get("next") or parsed.get("recommendation") or "The model did not return a next action; analyst review is required."

    try:
        confidence = str(int(float(str(confidence).replace("%", "").strip())))
    except Exception:
        confidence = str(confidence)

    return {
        "verdict": str(verdict).strip()[:80],
        "confidence": confidence,
        "reasoning": str(reasoning).strip()[:1200],
        "next_action": str(next_action).strip()[:600],
        "model": model,
        "latency_ms": latency_ms,
        "raw": str(raw).strip()[:4000],
    }


def build_prompt(payload: dict[str, Any]) -> str:
    analyst_prompt = str(payload.get("prompt") or "").strip()
    role = str(payload.get("model_role") or payload.get("role") or "triage").strip()
    rows = compact_rows(payload.get("rows", []), limit=20)

    if not analyst_prompt:
        analyst_prompt = "Summarise these Splunk rows for a SOC analyst."

    rows_json = json.dumps(rows, indent=2, ensure_ascii=False)

    return f"""
You are ARIA's local Splunk enrichment model.

You are operating in an air-gapped SOC environment.
You receive Splunk search rows and return concise analyst guidance.

Rules:
- Return strict JSON only.
- Do not include markdown.
- Do not invent evidence.
- Do not claim actions were executed.
- Do not recommend destructive action as already completed.
- If evidence is weak, say so.

Required JSON keys:
- verdict
- confidence
- reasoning
- next_action

Model role: {role}

Analyst prompt:
{analyst_prompt}

Splunk rows:
{rows_json}
""".strip()


def call_ollama(payload: dict[str, Any]) -> dict[str, Any]:
    model = choose_model(payload)
    prompt = build_prompt(payload)

    request_payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": KEEP_ALIVE,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_ctx": 4096,
        },
    }

    data = json.dumps(request_payload).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL + "/api/generate",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    started = time.time()

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        body = response.read().decode("utf-8", errors="replace")

    latency_ms = int((time.time() - started) * 1000)

    try:
        ollama_response = json.loads(body)
    except Exception:
        ollama_response = {}

    raw_text = str(ollama_response.get("response") or body or "").strip()
    parsed = extract_json_object(raw_text)

    return normalise_result(parsed, raw_text, model, latency_ms)


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "ARIA-LLM-Gateway/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(
            f"{self.client_address[0]} - - [{self.log_date_time_string()}] "
            + (fmt % args),
            flush=True,
        )

    def write_json(self, payload: dict[str, Any], status_code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/health"):
            self.write_json(
                {
                    "status": "ok",
                    "ollama_url": OLLAMA_URL,
                    "fast_model": FAST_MODEL,
                    "coder_model": CODER_MODEL,
                    "reasoning_model": REASONING_MODEL,
                    "pattern_a_default_model": FAST_MODEL,
                    "port": PORT,
                }
            )
            return

        self.write_json({"status": "error", "error": "not_found"}, status_code=404)

    def do_POST(self) -> None:
        if not self.path.startswith("/v1/enrich"):
            self.write_json({"status": "error", "error": "not_found"}, status_code=404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")

            try:
                payload = json.loads(raw_body) if raw_body.strip() else {}
            except Exception as exc:
                self.write_json(
                    {
                        "status": "error",
                        "error": "invalid_json",
                        "detail": str(exc),
                        "result": {
                            "verdict": "ERROR",
                            "confidence": "0",
                            "reasoning": "Gateway received invalid JSON.",
                            "next_action": "Check the Splunk custom command payload.",
                            "model": FAST_MODEL,
                            "latency_ms": 0,
                            "raw": raw_body[:1000],
                        },
                    },
                    status_code=200,
                )
                return

            result = call_ollama(payload)

            self.write_json(
                {
                    "status": "ok",
                    "result": result,
                },
                status_code=200,
            )

        except Exception as exc:
            # Avoid HTTP 500 for Splunk custom command reliability.
            self.write_json(
                {
                    "status": "error",
                    "error": type(exc).__name__,
                    "detail": str(exc)[:1000],
                    "result": {
                        "verdict": "ERROR",
                        "confidence": "0",
                        "reasoning": f"ARIA gateway error: {type(exc).__name__}: {str(exc)[:500]}",
                        "next_action": "Check aria-llm-gateway logs and Ollama connectivity.",
                        "model": FAST_MODEL,
                        "latency_ms": 0,
                        "raw": "",
                    },
                },
                status_code=200,
            )


def main() -> int:
    print("[ARIA LLM GATEWAY] starting", flush=True)
    print(f"[ARIA LLM GATEWAY] host={HOST} port={PORT}", flush=True)
    print(f"[ARIA LLM GATEWAY] ollama_url={OLLAMA_URL}", flush=True)
    print(f"[ARIA LLM GATEWAY] fast_model={FAST_MODEL}", flush=True)
    print(f"[ARIA LLM GATEWAY] reasoning_model={REASONING_MODEL}", flush=True)

    server = ThreadingHTTPServer((HOST, PORT), GatewayHandler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
