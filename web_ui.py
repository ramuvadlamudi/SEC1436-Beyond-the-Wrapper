from __future__ import annotations

import argparse
import dataclasses
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlparse

from aria.conversation_orchestrator import conversation_orchestrator
from aria.suppressed_exception_logger import log_suppressed_exception


APP_NAME = "ARIA"
APP_SUBTITLE = "Air-gapped Reasoning and Investigation Assistant"
APP_DESCRIPTION = "Evidence-first agentic Splunk SOC copilot"
SERVER_VERSION = "ARIAWebUI/8.0-analyst-workspace"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CHATS_DIR = DATA_DIR / "chats"
CHATS_DIR.mkdir(parents=True, exist_ok=True)
CHAT_LOCK = threading.RLock()
JOB_LOCK = threading.RLock()
JOBS: dict[str, dict[str, Any]] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(item) for item in value]
    if dataclasses.is_dataclass(value):
        return jsonable(dataclasses.asdict(value))
    if hasattr(value, "model_dump"):
        try:
            return jsonable(value.model_dump())
        except Exception:
            return str(value)
    if hasattr(value, "__dict__"):
        try:
            return jsonable(vars(value))
        except Exception:
            return str(value)
    return str(value)


def safe_chat_id(value: str) -> str:
    return "".join(character for character in value if character.isalnum() or character in {"-", "_"})


def chat_path(chat_id: str) -> Path:
    return CHATS_DIR / f"{safe_chat_id(chat_id)}.json"


def default_context_actions() -> list[str]:
    return [
        "Query the connected Splunk instance in natural language",
        "Explain SPL",
        "Investigate an analyst-supplied entity",
        "Build an evidence-qualified detection candidate",
    ]


def new_chat() -> dict[str, Any]:
    now = utc_now()
    chat = {
        "id": uuid.uuid4().hex,
        "title": "New investigation",
        "created_at": now,
        "updated_at": now,
        "messages": [],
        "last_result": None,
        "last_capability": None,
        "last_verdict": None,
        "last_confidence": None,
        "context_note": "New evidence-first investigation.",
        "context_actions": default_context_actions(),
        "pinned": False,
    }
    save_chat(chat)
    return chat


def save_chat(chat: dict[str, Any]) -> None:
    with CHAT_LOCK:
        chat["updated_at"] = utc_now()
        path = chat_path(str(chat["id"]))
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(jsonable(chat), indent=2, ensure_ascii=False), encoding="utf-8")
        temp.replace(path)


def load_chat(chat_id: str | None) -> dict[str, Any]:
    if chat_id:
        path = chat_path(chat_id)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                log_suppressed_exception(exc, component="aria.web_ui.load_chat")
    return new_chat()


def clear_chat(chat_id: str) -> dict[str, Any]:
    chat = load_chat(chat_id)
    chat.update(
        {
            "messages": [],
            "last_result": None,
            "last_capability": None,
            "last_verdict": None,
            "last_confidence": None,
            "context_note": "Investigation context was reset.",
            "context_actions": default_context_actions(),
        }
    )
    save_chat(chat)
    return chat


def delete_chat(chat_id: str) -> None:
    with CHAT_LOCK:
        path = chat_path(chat_id)
        if path.exists():
            path.unlink()


def rename_chat(chat_id: str, title: str) -> dict[str, Any]:
    chat = load_chat(chat_id)
    cleaned = " ".join(str(title or "").split()).strip()
    if not cleaned:
        raise ValueError("Investigation title cannot be empty.")
    chat["title"] = cleaned[:96]
    save_chat(chat)
    return chat


def set_chat_pinned(chat_id: str, pinned: bool) -> dict[str, Any]:
    chat = load_chat(chat_id)
    chat["pinned"] = bool(pinned)
    save_chat(chat)
    return chat


def short_timestamp(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value[:16]


def list_chats() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    with CHAT_LOCK:
        paths = list(CHATS_DIR.glob("*.json"))
    for path in paths:
        try:
            chat = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.web_ui.list_chats")
            continue
        user_preview = ""
        for message in reversed(chat.get("messages") or []):
            if message.get("role") == "user":
                user_preview = str(message.get("content") or "")
                break
        pending = any(message.get("status") == "thinking" for message in chat.get("messages") or [])
        output.append(
            {
                "id": chat.get("id"),
                "title": chat.get("title") or "New investigation",
                "updated_at": chat.get("updated_at"),
                "updated_label": short_timestamp(chat.get("updated_at")),
                "last_capability": chat.get("last_capability"),
                "last_verdict": "ARIA_WORKING" if pending else chat.get("last_verdict"),
                "last_confidence": chat.get("last_confidence"),
                "last_message": user_preview[:140],
                "message_count": len(chat.get("messages") or []),
                "pinned": bool(chat.get("pinned", False)),
            }
        )
    output.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
    output.sort(key=lambda item: bool(item.get("pinned")), reverse=True)
    return output[:100]


def append_message(
    chat: dict[str, Any],
    *,
    role: str,
    content: str,
    capability: str | None = None,
    route: str | None = None,
    duration_seconds: float | None = None,
    verdict: str | None = None,
    confidence: int | None = None,
    structured_result: dict[str, Any] | None = None,
    status: str = "complete",
    job_id: str | None = None,
    progress: dict[str, Any] | None = None,
    followups: list[str] | None = None,
) -> str:
    message_id = uuid.uuid4().hex
    chat.setdefault("messages", []).append(
        {
            "id": message_id,
            "role": role,
            "content": content,
            "capability": capability,
            "route": route,
            "duration_seconds": duration_seconds,
            "verdict": verdict,
            "confidence": confidence,
            "structured_result": structured_result,
            "status": status,
            "job_id": job_id,
            "progress": progress,
            "followups": list(followups or []),
            "created_at": utc_now(),
        }
    )
    return message_id


def update_chat_title(chat: dict[str, Any], question: str) -> None:
    if chat.get("title") and chat.get("title") != "New investigation":
        return
    title = " ".join(question.strip().split())
    chat["title"] = (title[:61] + "...") if len(title) > 64 else (title or "New investigation")


def result_details(result: dict[str, Any] | None) -> tuple[str | None, int | None]:
    if not isinstance(result, dict):
        return None, None
    finding = result.get("finding")
    confidence = result.get("confidence")
    verdict = finding.get("verdict") if isinstance(finding, dict) else None
    score = confidence.get("score") if isinstance(confidence, dict) else None
    try:
        score = int(score) if score is not None else None
    except Exception:
        score = None
    return str(verdict) if verdict else None, score


def _find_message(chat: dict[str, Any], message_id: str) -> dict[str, Any] | None:
    for message in chat.get("messages") or []:
        if message.get("id") == message_id:
            return message
    return None


def _progress_snapshot(stage: str, label: str, detail: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "stage": stage,
        "label": label,
        "detail": detail,
        "events": events[-16:],
        "updated_at": utc_now(),
    }


def start_chat_job(chat_id: str | None, question: str) -> dict[str, Any]:
    question = str(question or "").strip()
    if not question:
        return {"ok": False, "error": "Analyst message is empty."}

    chat = load_chat(chat_id)
    if any(message.get("status") == "thinking" for message in chat.get("messages") or []):
        return {"ok": False, "error": "ARIA is already working on this investigation. Wait for it to finish or start a new investigation."}

    prior_history = list(chat.get("messages") or [])[-12:]
    prior_result = chat.get("last_result")
    job_id = uuid.uuid4().hex
    now = utc_now()

    append_message(chat, role="user", content=question)
    assistant_message_id = append_message(
        chat,
        role="assistant",
        content="",
        capability="DETERMINISTIC_ROUTING",
        route="ARIA_V3_ROUTER",
        status="thinking",
        job_id=job_id,
        progress=_progress_snapshot(
            "queued",
            "Understanding your request",
            "ARIA's deterministic control plane will select the isolated product agent before any optional model reasoning.",
            [
                {
                    "stage": "queued",
                    "label": "Request accepted",
                    "detail": "The message was added to the conversation and is being routed by deterministic capability grammar.",
                    "status": "active",
                    "at": now,
                }
            ],
        ),
    )
    update_chat_title(chat, question)
    save_chat(chat)

    job = {
        "id": job_id,
        "chat_id": chat["id"],
        "assistant_message_id": assistant_message_id,
        "status": "running",
        "stage": "queued",
        "label": "Understanding your request",
        "detail": "ARIA is applying deterministic route precedence before deciding whether read-only Splunk access is needed.",
        "events": [],
        "started_at": now,
        "updated_at": now,
        "error": None,
    }
    with JOB_LOCK:
        JOBS[job_id] = job

    worker = threading.Thread(
        target=_run_chat_job,
        args=(job_id, question, prior_history, prior_result),
        daemon=True,
        name=f"aria-job-{job_id[:8]}",
    )
    worker.start()
    return {"ok": True, "job": jsonable(job), "chat": chat}


def _run_chat_job(
    job_id: str,
    question: str,
    prior_history: list[Any],
    prior_result: Any,
) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return

    chat_id = str(job["chat_id"])
    assistant_message_id = str(job["assistant_message_id"])
    started = time.monotonic()
    progress_events: list[dict[str, Any]] = []
    progress_lock = threading.RLock()

    def progress(stage: str, label: str, detail: str = "") -> None:
        nonlocal progress_events
        with progress_lock:
            now = utc_now()
            for event in progress_events:
                if event.get("status") == "active":
                    event["status"] = "complete"
                    event["completed_at"] = now
            progress_events.append(
                {
                    "stage": stage,
                    "label": label,
                    "detail": detail,
                    "status": "active" if stage not in {"complete", "error"} else stage,
                    "at": now,
                }
            )
            snapshot = _progress_snapshot(stage, label, detail, progress_events)

        with JOB_LOCK:
            current = JOBS.get(job_id)
            if current:
                current.update(
                    {
                        "stage": stage,
                        "label": label,
                        "detail": detail,
                        "events": list(progress_events),
                        "updated_at": now,
                    }
                )

        chat = load_chat(chat_id)
        pending = _find_message(chat, assistant_message_id)
        if pending:
            pending["progress"] = snapshot
            save_chat(chat)

    try:
        decision = conversation_orchestrator.route(
            question=question,
            last_result=prior_result,
            history=prior_history,
            progress=progress,
        )
        duration = round(time.monotonic() - started, 2)
        structured = jsonable(getattr(decision, "result", None))
        verdict, confidence = result_details(structured)

        chat = load_chat(chat_id)
        pending = _find_message(chat, assistant_message_id)
        if pending:
            pending.update(
                {
                    "content": str(decision.answer or ""),
                    "capability": str(decision.capability or "UNKNOWN"),
                    "route": str(decision.route or "ARIA_V3_ORCHESTRATOR"),
                    "duration_seconds": duration,
                    "verdict": verdict,
                    "confidence": confidence,
                    "structured_result": structured,
                    "followups": list(decision.context_actions or []),
                    "status": "complete",
                    "progress": _progress_snapshot(
                        "complete",
                        "Response ready",
                        "ARIA completed the routed request and prepared aligned follow-up prompts.",
                        progress_events,
                    ),
                }
            )
        chat["last_result"] = structured
        chat["last_capability"] = decision.capability
        chat["last_verdict"] = verdict
        chat["last_confidence"] = confidence
        chat["context_note"] = decision.context_note or "ARIA completed the evidence-first request path."
        chat["context_actions"] = list(decision.context_actions or [])
        save_chat(chat)

        with JOB_LOCK:
            current = JOBS.get(job_id)
            if current:
                current.update(
                    {
                        "status": "complete",
                        "stage": "complete",
                        "label": "Response ready",
                        "detail": "The routed response and follow-up prompts are ready.",
                        "events": progress_events,
                        "updated_at": utc_now(),
                        "duration_seconds": duration,
                    }
                )
    except Exception as exc:
        duration = round(time.monotonic() - started, 2)
        log_suppressed_exception(exc, component="aria.web_ui.background_job")
        error_text = f"{exc.__class__.__name__}: {exc}"
        chat = load_chat(chat_id)
        pending = _find_message(chat, assistant_message_id)
        if pending:
            pending.update(
                {
                    "content": (
                        "## ARIA request stopped\n\n"
                        "ARIA could not complete the evidence-first workflow and did not fabricate a result.\n\n"
                        f"**Error:** `{error_text}`\n\n"
                        "Review local Ollama and Splunk connectivity, then retry."
                    ),
                    "capability": "COPILOT_ERROR",
                    "duration_seconds": duration,
                    "verdict": "WORKFLOW_ERROR",
                    "confidence": 0,
                    "status": "error",
                    "progress": _progress_snapshot("error", "Investigation stopped", error_text, progress_events),
                }
            )
        chat["last_capability"] = "COPILOT_ERROR"
        chat["last_verdict"] = "WORKFLOW_ERROR"
        chat["last_confidence"] = 0
        save_chat(chat)
        with JOB_LOCK:
            current = JOBS.get(job_id)
            if current:
                current.update(
                    {
                        "status": "error",
                        "stage": "error",
                        "label": "Investigation stopped",
                        "detail": error_text,
                        "error": error_text,
                        "updated_at": utc_now(),
                        "duration_seconds": duration,
                    }
                )


def get_job(job_id: str) -> dict[str, Any] | None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        return jsonable(job) if job else None


def handle_chat_message(chat_id: str | None, question: str) -> dict[str, Any]:
    """Synchronous compatibility endpoint used by older clients."""
    question = str(question or "").strip()
    if not question:
        return {"ok": False, "error": "Analyst message is empty."}
    chat = load_chat(chat_id)
    prior_history = list(chat.get("messages") or [])[-12:]
    prior_result = chat.get("last_result")
    started = time.monotonic()
    try:
        decision = conversation_orchestrator.route(question=question, last_result=prior_result, history=prior_history)
    except Exception as exc:
        log_suppressed_exception(exc, component="aria.web_ui.handle_chat_message")
        return {"ok": False, "error": f"ARIA request failed: {exc.__class__.__name__}: {exc}", "chat": chat}
    duration = round(time.monotonic() - started, 2)
    structured = jsonable(getattr(decision, "result", None))
    verdict, confidence = result_details(structured)
    append_message(chat, role="user", content=question)
    append_message(
        chat,
        role="assistant",
        content=str(decision.answer or ""),
        capability=str(decision.capability or "UNKNOWN"),
        route=str(decision.route or "ARIA_V3_ORCHESTRATOR"),
        duration_seconds=duration,
        verdict=verdict,
        confidence=confidence,
        structured_result=structured,
        followups=list(decision.context_actions or []),
    )
    update_chat_title(chat, question)
    chat["last_result"] = structured
    chat["last_capability"] = decision.capability
    chat["last_verdict"] = verdict
    chat["last_confidence"] = confidence
    chat["context_note"] = decision.context_note or "ARIA completed the evidence-first request path."
    chat["context_actions"] = list(decision.context_actions or [])
    save_chat(chat)
    return {"ok": True, "chat": chat}


def read_product_text(relative: str, default: str = "unknown") -> str:
    try:
        return (BASE_DIR / relative).read_text(encoding="utf-8").strip() or default
    except Exception:
        return default


def engine_status() -> dict[str, Any]:
    return {
        "available": True,
        "product": APP_NAME,
        "description": APP_DESCRIPTION,
        "version": read_product_text("product/VERSION"),
        "release_channel": read_product_text("product/RELEASE_CHANNEL"),
        "engine": "Evidence-First Copilot",
        "splunk": "Live read-only queries per investigation",
        "llm": "Local fast planner plus bounded reasoning model",
        "qualification": "Observed fields, observed values and live co-occurrence",
        "safety_policy": (BASE_DIR / "product" / "safety_policy.json").exists(),
        "evidence_policy": (BASE_DIR / "product" / "evidence_policy.json").exists(),
        "risk_policy": (BASE_DIR / "product" / "risk_policy.json").exists(),
    }


HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARIA Evidence-First SOC Copilot</title>
<style>
:root {
  color-scheme: dark;
  --bg: #070a0f;
  --surface: #0d131c;
  --surface-2: #121b27;
  --surface-3: #172333;
  --border: #263447;
  --border-soft: rgba(148, 165, 188, .16);
  --text: #eef4ff;
  --muted: #94a5bc;
  --accent: #8268ff;
  --accent-2: #17d9b1;
  --danger: #ff6b84;
  --warning: #ffca6a;
  --code: #071018;
  --left-width: 278px;
  --right-width: 336px;
}
* { box-sizing: border-box; }
html, body { height: 100%; min-height: 0; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  overflow: hidden;
  overscroll-behavior: none;
}
button, textarea, input { font: inherit; }
button { color: inherit; }
button:focus-visible, input:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.hidden { display: none !important; }
.small { color: var(--muted); font-size: 11px; line-height: 1.45; }

.app {
  height: 100vh;
  height: 100dvh;
  height: var(--aria-viewport-height, 100dvh);
  max-height: var(--aria-viewport-height, 100dvh);
  min-height: 0;
  display: grid;
  grid-template-columns: var(--left-width) minmax(0, 1fr) var(--right-width);
  position: relative;
  overflow: hidden;
  transition: grid-template-columns .18s ease;
}
.app.left-collapsed { grid-template-columns: 0 minmax(0, 1fr) var(--right-width); }
.app.right-collapsed { grid-template-columns: var(--left-width) minmax(0, 1fr) 0; }
.app.left-collapsed.right-collapsed { grid-template-columns: 0 minmax(0, 1fr) 0; }
.panel { min-width: 0; background: var(--surface); }

.left-panel {
  min-height: 0;
  height: 100%;
  border-right: 1px solid var(--border);
  display: grid;
  grid-template-rows: auto auto auto minmax(0, 1fr) auto;
  overflow: hidden;
  transition: transform .2s ease, opacity .18s ease;
}
.app.left-collapsed .left-panel { opacity: 0; pointer-events: none; }
.left-header { padding: 16px 14px 10px; }
.brand-main { font-size: 26px; font-weight: 850; letter-spacing: .08em; }
.brand-sub { margin-top: 4px; color: var(--muted); font-size: 12px; line-height: 1.4; }
.brand-mode {
  display: inline-flex;
  margin-top: 9px;
  padding: 5px 8px;
  border: 1px solid rgba(23, 217, 177, .38);
  background: rgba(23, 217, 177, .08);
  border-radius: 999px;
  color: var(--accent-2);
  font-size: 10px;
  font-weight: 800;
}
.new-chat {
  margin: 0 12px 10px;
  border: 0;
  border-radius: 11px;
  padding: 11px 12px;
  background: var(--accent);
  color: #fff;
  font-weight: 800;
  cursor: pointer;
}
.new-chat:hover { filter: brightness(1.06); }
.chat-search-wrap { padding: 0 12px 10px; }
.chat-search {
  width: 100%;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface-2);
  color: var(--text);
  padding: 9px 10px;
}
.chat-search::placeholder { color: var(--muted); }
.left-section-label {
  padding: 0 14px 7px;
  color: var(--muted);
  font-size: 10px;
  font-weight: 850;
  letter-spacing: .13em;
  text-transform: uppercase;
}
.chat-list {
  min-height: 0;
  overflow-y: auto;
  padding: 0 8px 12px;
  scrollbar-gutter: stable;
}
.chat-row {
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 32px;
  gap: 2px;
  margin-bottom: 5px;
  border: 1px solid transparent;
  border-radius: 10px;
  background: transparent;
}
.chat-row:hover { background: rgba(255,255,255,.035); }
.chat-row.active { border-color: rgba(23,217,177,.55); background: rgba(23,217,177,.07); }
.chat-main {
  min-width: 0;
  border: 0;
  background: transparent;
  text-align: left;
  padding: 10px 4px 10px 10px;
  cursor: pointer;
}
.chat-title-line { display: flex; align-items: center; gap: 6px; min-width: 0; }
.chat-pin { color: var(--warning); font-size: 10px; flex: 0 0 auto; }
.chat-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; font-weight: 720; }
.chat-meta { margin-top: 5px; color: var(--muted); font-size: 10px; display: flex; justify-content: space-between; gap: 6px; }
.chat-meta span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chat-menu-button {
  align-self: center;
  width: 28px;
  height: 28px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  opacity: 0;
}
.chat-row:hover .chat-menu-button, .chat-row.active .chat-menu-button, .chat-menu-button[aria-expanded="true"] { opacity: 1; }
.chat-menu-button:hover { background: var(--surface-3); color: var(--text); }
.chat-popover {
  position: absolute;
  top: 36px;
  right: 4px;
  z-index: 30;
  width: 166px;
  padding: 5px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface-2);
  box-shadow: 0 16px 36px rgba(0,0,0,.35);
}
.chat-popover button {
  width: 100%;
  border: 0;
  border-radius: 7px;
  background: transparent;
  padding: 8px 9px;
  text-align: left;
  cursor: pointer;
  font-size: 12px;
}
.chat-popover button:hover { background: var(--surface-3); }
.chat-popover .danger { color: var(--danger); }
.left-footer { border-top: 1px solid var(--border); padding: 10px 12px; }
.connection-row { display: flex; justify-content: space-between; gap: 8px; font-size: 10px; color: var(--muted); }
.connection-dot { color: var(--accent-2); }

.center-panel {
  min-height: 0;
  min-width: 0;
  height: 100%;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  overflow: hidden;
  background: var(--bg);
}
.topbar {
  min-height: 60px;
  padding: 11px 16px;
  border-bottom: 1px solid var(--border);
  background: rgba(13, 19, 28, .96);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  z-index: 5;
}
.top-left, .top-right { display: flex; align-items: center; gap: 9px; min-width: 0; }
.icon-button {
  flex: 0 0 auto;
  border: 1px solid var(--border);
  background: var(--surface-2);
  border-radius: 9px;
  min-width: 34px;
  height: 34px;
  padding: 0 9px;
  cursor: pointer;
}
.icon-button:hover { border-color: var(--accent); background: var(--surface-3); }
.top-title-wrap { min-width: 0; }
.top-title { font-weight: 780; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.top-sub { margin-top: 2px; color: var(--muted); font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.status-cluster { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 5px; }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 7px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface-2);
  color: var(--muted);
  font-size: 10px;
  font-weight: 750;
}
.badge.good { color: var(--accent-2); border-color: rgba(23,217,177,.35); }
.badge.warn { color: var(--warning); border-color: rgba(255,202,106,.35); }
.badge.danger { color: var(--danger); border-color: rgba(255,107,132,.35); }

.messages {
  height: 100%;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  overscroll-behavior-y: contain;
  -webkit-overflow-scrolling: touch;
  scrollbar-gutter: stable;
  scroll-behavior: smooth;
  padding: 24px 26px 48px;
  position: relative;
}
.messages::-webkit-scrollbar, .chat-list::-webkit-scrollbar, .right-body::-webkit-scrollbar { width: 10px; }
.messages::-webkit-scrollbar-thumb, .chat-list::-webkit-scrollbar-thumb, .right-body::-webkit-scrollbar-thumb {
  background: var(--border);
  border: 3px solid transparent;
  border-radius: 999px;
  background-clip: padding-box;
}
.empty { max-width: 880px; margin: 8vh auto 0; text-align: center; color: var(--muted); }
.empty h1 { color: var(--text); font-size: 27px; margin-bottom: 9px; }
.empty-grid { margin-top: 22px; display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 10px; text-align: left; }
.empty-item { border: 1px solid var(--border); background: var(--surface-2); border-radius: 12px; padding: 13px; cursor: pointer; }
.empty-item:hover { border-color: var(--accent-2); }
.empty-item strong { display: block; color: var(--text); margin-bottom: 5px; }
.message { max-width: 1050px; margin: 0 auto 25px; scroll-margin: 90px 0 150px; }
.message.user { display: flex; flex-direction: column; align-items: flex-end; }
.message-head { display: flex; align-items: center; flex-wrap: wrap; gap: 7px; width: 100%; margin-bottom: 7px; }
.message.user .message-head { justify-content: flex-end; }
.avatar { width: 28px; height: 28px; border-radius: 9px; display: grid; place-items: center; font-size: 11px; font-weight: 850; background: var(--surface-3); }
.message.user .avatar { background: rgba(130,104,255,.2); color: #d4caff; }
.message.assistant .avatar { background: rgba(23,217,177,.13); color: var(--accent-2); }
.role { font-size: 12px; font-weight: 730; }
.message-card { line-height: 1.58; overflow-wrap: anywhere; }
.message.user .message-card { max-width: 82%; border: 1px solid rgba(130,104,255,.35); background: rgba(130,104,255,.1); border-radius: 16px 16px 5px 16px; padding: 13px 15px; }
.message.assistant .message-card { width: 100%; border-left: 2px solid rgba(23,217,177,.45); padding: 2px 0 2px 18px; }
.message-tools { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
.tool-button { border: 1px solid var(--border); background: transparent; border-radius: 8px; padding: 6px 9px; color: var(--muted); font-size: 10px; cursor: pointer; }
.tool-button:hover { color: var(--text); border-color: var(--accent); }
.message-followups { margin-top: 14px; padding-top: 11px; border-top: 1px solid var(--border); }
.followup-label { color: var(--muted); font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 8px; }
.followup-list { display: flex; flex-wrap: wrap; gap: 7px; }
.followup-chip { max-width: 100%; border: 1px solid rgba(23,217,177,.28); background: rgba(23,217,177,.055); border-radius: 999px; padding: 7px 10px; color: var(--text); font-size: 11px; text-align: left; cursor: pointer; }
.followup-chip:hover { border-color: var(--accent-2); background: rgba(23,217,177,.1); }
.markdown h1, .markdown h2, .markdown h3 { margin: 1.3em 0 .55em; line-height: 1.25; }
.markdown h1 { font-size: 21px; }
.markdown h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.markdown h3 { font-size: 15px; }
.markdown p { margin: .65em 0; }
.markdown ul, .markdown ol { padding-left: 22px; }
.markdown li { margin: .3em 0; }
.markdown code { background: var(--code); border: 1px solid var(--border); border-radius: 5px; padding: 1px 5px; }
.markdown pre { background: var(--code); border: 1px solid var(--border); border-radius: 10px; padding: 13px; overflow: auto; white-space: pre; }
.markdown pre code { border: 0; padding: 0; }
.table-wrap { overflow-x: auto; margin: 12px 0; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { text-align: left; vertical-align: top; border: 1px solid var(--border); padding: 8px; }
th { background: var(--surface-2); }

.thinking-card { max-width: 900px; border: 1px solid rgba(23,217,177,.3); background: rgba(23,217,177,.045); border-radius: 13px; padding: 14px 15px; }
.thinking-title { display: flex; align-items: center; gap: 10px; font-weight: 780; }
.spinner { width: 17px; height: 17px; border: 2px solid rgba(23,217,177,.2); border-top-color: var(--accent-2); border-radius: 50%; animation: spin .85s linear infinite; }
.elapsed { margin-left: auto; color: var(--muted); font-size: 10px; }
.thinking-stage { margin-top: 7px; color: var(--text); font-size: 13px; }
.thinking-detail { margin-top: 4px; color: var(--muted); font-size: 11px; line-height: 1.45; }
.progress-track { height: 5px; margin: 12px 0; background: var(--surface-3); border-radius: 999px; overflow: hidden; }
.progress-pulse { height: 100%; width: 36%; background: var(--accent-2); border-radius: 999px; animation: travel 1.6s ease-in-out infinite; }
.step-list { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
.step { display: grid; grid-template-columns: 17px minmax(0,1fr); gap: 7px; color: var(--muted); font-size: 11px; }
.step-dot { width: 10px; height: 10px; margin-top: 3px; border: 1px solid var(--border); border-radius: 50%; }
.step.complete .step-dot { background: var(--accent-2); border-color: var(--accent-2); }
.step.active { color: var(--text); }
.step.active .step-dot { border-color: var(--accent-2); box-shadow: 0 0 0 3px rgba(23,217,177,.12); }

.composer { border-top: 1px solid var(--border); background: var(--surface); padding: 8px 18px 12px; z-index: 6; }
.composer-shell { max-width: 1050px; margin: 0 auto; }
.active-job-bar { display: none; align-items: center; gap: 9px; margin: 0 0 7px; padding: 7px 10px; border: 1px solid rgba(23,217,177,.28); background: rgba(23,217,177,.055); border-radius: 10px; color: var(--muted); font-size: 11px; }
.active-job-bar.visible { display: flex; }
.active-job-stage { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); }
.active-job-button { margin-left: auto; border: 0; background: transparent; color: var(--accent-2); cursor: pointer; font-weight: 750; }
.input-shell { border: 1px solid var(--border); background: var(--surface-2); border-radius: 14px; padding: 9px 10px 8px; }
.input-shell:focus-within { border-color: var(--accent); }
textarea { width: 100%; min-height: 54px; max-height: 170px; resize: vertical; border: 0; background: transparent; color: var(--text); padding: 3px; outline: none; }
.composer-actions { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-top: 5px; }
.helper { color: var(--muted); font-size: 10px; }
.send-button { border: 0; border-radius: 9px; padding: 9px 15px; background: var(--accent); color: white; font-weight: 780; cursor: pointer; }
.send-button:disabled { opacity: .5; cursor: wait; }
.jump-latest { position: absolute; right: calc(var(--right-width) + 24px); bottom: 120px; z-index: 8; display: none; border: 1px solid var(--border); background: var(--surface-3); border-radius: 999px; padding: 8px 12px; cursor: pointer; font-size: 11px; }
.app.right-collapsed .jump-latest { right: 24px; }
.jump-latest.visible { display: block; }

.right-panel {
  min-height: 0;
  height: 100%;
  border-left: 1px solid var(--border);
  display: grid;
  grid-template-rows: auto auto minmax(0,1fr);
  overflow: hidden;
  transition: transform .2s ease, opacity .18s ease;
}
.app.right-collapsed .right-panel { opacity: 0; pointer-events: none; }
.right-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 14px 13px 10px; }
.right-title { font-size: 13px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
.right-tabs { display: grid; grid-template-columns: repeat(3, 1fr); gap: 4px; padding: 0 10px 10px; border-bottom: 1px solid var(--border); }
.right-tab { border: 0; border-radius: 8px; background: transparent; color: var(--muted); padding: 8px 5px; cursor: pointer; font-size: 11px; font-weight: 750; }
.right-tab:hover { background: var(--surface-2); color: var(--text); }
.right-tab.active { background: var(--surface-3); color: var(--accent-2); }
.right-body { min-height: 0; overflow-y: auto; padding: 10px; scrollbar-gutter: stable; }
.workspace-section { display: none; }
.workspace-section.active { display: block; }
.workspace-card { border: 1px solid var(--border); background: var(--surface-2); border-radius: 11px; padding: 11px; margin-bottom: 9px; }
.workspace-card-title { margin-bottom: 9px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }
.metric-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 7px; }
.metric { min-width: 0; border: 1px solid var(--border); background: var(--surface-3); border-radius: 9px; padding: 8px; }
.metric-label { color: var(--muted); font-size: 9px; text-transform: uppercase; letter-spacing: .08em; }
.metric-value { margin-top: 4px; font-size: 13px; font-weight: 780; overflow-wrap: anywhere; }
.detail-row { padding: 7px 0; border-top: 1px solid var(--border-soft); }
.detail-row:first-child { border-top: 0; padding-top: 0; }
.detail-label { color: var(--muted); font-size: 10px; }
.detail-value { margin-top: 3px; font-size: 12px; line-height: 1.4; overflow-wrap: anywhere; }
.action-list { display: flex; flex-direction: column; gap: 7px; }
.action-button { width: 100%; border: 1px solid var(--border); background: var(--surface-2); border-radius: 9px; padding: 9px 10px; text-align: left; cursor: pointer; font-size: 11px; line-height: 1.35; }
.action-button:hover { border-color: var(--accent-2); background: var(--surface-3); }
.source, .requirement, .search-item, .claim, .factor { padding: 8px 0; border-top: 1px solid var(--border-soft); }
.source:first-child, .requirement:first-child, .search-item:first-child, .claim:first-child, .factor:first-child { border-top: 0; padding-top: 0; }
.source-name { font-size: 11px; font-weight: 720; line-height: 1.4; }
.source-reason { margin-top: 3px; color: var(--muted); font-size: 10px; line-height: 1.45; }

.overlay { position: fixed; inset: 0; z-index: 40; background: rgba(0,0,0,.52); opacity: 0; pointer-events: none; transition: opacity .18s ease; }
.overlay.open { opacity: 1; pointer-events: auto; }
.modal-backdrop { position: fixed; inset: 0; z-index: 70; display: grid; place-items: center; background: rgba(0,0,0,.62); padding: 20px; }
.modal { width: min(430px, 100%); border: 1px solid var(--border); border-radius: 14px; background: var(--surface); box-shadow: 0 24px 70px rgba(0,0,0,.55); padding: 17px; }
.modal h2 { margin: 0 0 8px; font-size: 18px; }
.modal p { margin: 0 0 14px; color: var(--muted); font-size: 12px; line-height: 1.5; }
.modal input { width: 100%; border: 1px solid var(--border); border-radius: 9px; background: var(--surface-2); color: var(--text); padding: 10px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.modal-button { border: 1px solid var(--border); border-radius: 9px; background: var(--surface-2); padding: 8px 12px; cursor: pointer; }
.modal-button.primary { border-color: var(--accent); background: var(--accent); color: #fff; }
.modal-button.danger { border-color: rgba(255,107,132,.4); background: rgba(255,107,132,.1); color: var(--danger); }
.toast { position: fixed; left: 50%; bottom: 92px; z-index: 90; transform: translateX(-50%) translateY(15px); opacity: 0; pointer-events: none; border: 1px solid var(--border); border-radius: 9px; background: var(--surface-3); padding: 8px 12px; color: var(--text); font-size: 11px; transition: .18s ease; }
.toast.visible { opacity: 1; transform: translateX(-50%) translateY(0); }

@keyframes spin { to { transform: rotate(360deg); } }
@keyframes travel { 0% { transform: translateX(-105%); } 50% { transform: translateX(180%); } 100% { transform: translateX(-105%); } }

@media (max-width: 1260px) {
  :root { --left-width: 248px; --right-width: 306px; }
  .status-cluster .optional-status { display: none; }
}
@media (max-width: 1000px) {
  .app, .app.left-collapsed, .app.right-collapsed, .app.left-collapsed.right-collapsed { grid-template-columns: minmax(0,1fr); }
  .left-panel, .right-panel { position: fixed; top: 0; bottom: 0; z-index: 50; width: min(86vw, 330px); opacity: 1 !important; pointer-events: auto !important; box-shadow: 0 18px 60px rgba(0,0,0,.5); }
  .left-panel { left: 0; transform: translateX(-104%); }
  .left-panel.open { transform: translateX(0); }
  .right-panel { right: 0; transform: translateX(104%); }
  .right-panel.open { transform: translateX(0); }
  .jump-latest, .app.right-collapsed .jump-latest { right: 18px; }
  .status-cluster { display: none; }
}
@media (max-width: 660px) {
  .messages { padding: 18px 13px 40px; }
  .composer { padding: 8px 10px 10px; }
  .topbar { padding: 10px; }
  .top-sub { display: none; }
  .message.user .message-card { max-width: 92%; }
  .empty-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="app" id="app">
  <aside class="panel left-panel" id="left-panel" aria-label="Investigations">
    <div class="left-header">
      <div class="brand-main">ARIA</div>
      <div class="brand-sub">Air-gapped Reasoning and Investigation Assistant</div>
      <div class="brand-mode">EVIDENCE-FIRST · READ-ONLY</div>
    </div>
    <button class="new-chat" id="new-chat">＋ New investigation</button>
    <div class="chat-search-wrap">
      <input class="chat-search" id="chat-search" type="search" placeholder="Search investigations" aria-label="Search investigations">
    </div>
    <div class="chat-list" id="chat-list" aria-live="polite"></div>
    <div class="left-footer">
      <div class="connection-row"><span><span class="connection-dot">●</span> Splunk read-only</span><span>Local LLM</span></div>
    </div>
  </aside>

  <main class="center-panel">
    <header class="topbar">
      <div class="top-left">
        <button class="icon-button" id="toggle-left" aria-label="Toggle investigations">☰</button>
        <div class="top-title-wrap">
          <div class="top-title" id="current-title">New investigation</div>
          <div class="top-sub">Local LLM hypotheses + live Splunk facts + deterministic evidence controls</div>
        </div>
      </div>
      <div class="top-right">
        <div class="status-cluster">
          <span class="badge good">Splunk · read-only</span>
          <span class="badge good">LLM · local</span>
          <span class="badge optional-status">Evidence-qualified</span>
          <span class="badge" id="version-badge">unknown</span>
        </div>
        <button class="icon-button" id="current-chat-menu" aria-label="Investigation options">•••</button>
        <button class="icon-button" id="toggle-right" aria-label="Toggle analyst workspace">Workspace</button>
      </div>
    </header>

    <section class="messages" id="messages" aria-live="polite"></section>
    <button class="jump-latest" id="jump-latest">Latest message ↓</button>

    <footer class="composer">
      <div class="composer-shell">
        <div class="active-job-bar" id="active-job-bar">
          <span class="spinner"></span>
          <span class="active-job-stage" id="active-job-stage">ARIA is working</span>
          <span id="active-job-elapsed">0s</span>
          <button class="active-job-button" id="view-progress">View progress</button>
        </div>
        <div class="input-shell">
          <textarea id="prompt" placeholder="Ask ARIA to explain SPL, query Splunk, investigate an entity, test a hypothesis, or prepare a detection/TDIR workflow…"></textarea>
          <div class="composer-actions">
            <div class="helper">Enter to send · Shift+Enter for a new line</div>
            <button class="send-button" id="send">Send</button>
          </div>
        </div>
      </div>
    </footer>
  </main>

  <aside class="panel right-panel" id="right-panel" aria-label="Analyst workspace">
    <div class="right-header">
      <div class="right-title">Analyst workspace</div>
      <button class="icon-button" id="close-right" aria-label="Close analyst workspace">✕</button>
    </div>
    <div class="right-tabs" role="tablist">
      <button class="right-tab active" data-workspace-tab="overview" role="tab">Overview</button>
      <button class="right-tab" data-workspace-tab="evidence" role="tab">Evidence</button>
      <button class="right-tab" data-workspace-tab="actions" role="tab">Actions</button>
    </div>
    <div class="right-body">
      <section class="workspace-section active" id="workspace-overview"></section>
      <section class="workspace-section" id="workspace-evidence"></section>
      <section class="workspace-section" id="workspace-actions"></section>
    </div>
  </aside>
</div>

<div class="overlay" id="overlay"></div>
<div class="modal-backdrop hidden" id="modal-backdrop" role="presentation">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <h2 id="modal-title">Investigation</h2>
    <p id="modal-copy"></p>
    <input class="hidden" id="modal-input" type="text" maxlength="96" aria-label="Investigation name">
    <div class="modal-actions">
      <button class="modal-button" id="modal-cancel">Cancel</button>
      <button class="modal-button primary" id="modal-confirm">Confirm</button>
    </div>
  </div>
</div>
<div class="toast" id="toast" role="status"></div>

<script>
const state = {
  chatId: null,
  chat: null,
  chats: [],
  status: null,
  busy: false,
  currentJob: null,
  pollTimer: null,
  followLatest: true,
  leftOpen: window.matchMedia("(min-width:1001px)").matches,
  rightOpen: window.matchMedia("(min-width:1001px)").matches,
  workspaceTab: "overview",
  openChatMenuId: null,
  modal: null,
};

function syncViewportHeight() {
  const viewport = window.visualViewport;
  const height = Math.max(320, Math.round((viewport && viewport.height) || window.innerHeight || document.documentElement.clientHeight || 720));
  document.documentElement.style.setProperty("--aria-viewport-height", `${height}px`);
}
function isCompact() { return window.matchMedia("(max-width:1000px)").matches; }
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function inlineMarkdown(value) {
  return String(value ?? "")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");
}
function markdownToHtml(source) {
  const codeBlocks = [];
  let text = String(source ?? "").replace(/```([^\n]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const token = `@@CODE${codeBlocks.length}@@`;
    codeBlocks.push(`<pre><code data-language="${escapeHtml(lang.trim())}">${escapeHtml(code.trimEnd())}</code></pre>`);
    return token;
  });
  text = escapeHtml(text);
  const lines = text.split("\n");
  const output = [];
  let list = null;
  const closeList = () => { if (list) { output.push(`</${list}>`); list = null; } };
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const next = lines[index + 1] || "";
    if (/^\|.*\|$/.test(line.trim()) && /^\|?\s*:?-+/.test(next.trim())) {
      closeList();
      const heads = line.trim().replace(/^\||\|$/g, "").split("|").map(item => item.trim());
      index += 1;
      const rows = [];
      while (index + 1 < lines.length && /^\|.*\|$/.test(lines[index + 1].trim())) {
        index += 1;
        rows.push(lines[index].trim().replace(/^\||\|$/g, "").split("|").map(item => item.trim()));
      }
      output.push(`<div class="table-wrap"><table><thead><tr>${heads.map(item => `<th>${inlineMarkdown(item)}</th>`).join("")}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(item => `<td>${inlineMarkdown(item)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    if (heading) {
      closeList();
      const level = heading[1].length;
      output.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    if (bullet) {
      if (list !== "ul") { closeList(); list = "ul"; output.push("<ul>"); }
      output.push(`<li>${inlineMarkdown(bullet[1])}</li>`);
      continue;
    }
    const ordered = line.match(/^\s*\d+\.\s+(.*)$/);
    if (ordered) {
      if (list !== "ol") { closeList(); list = "ol"; output.push("<ol>"); }
      output.push(`<li>${inlineMarkdown(ordered[1])}</li>`);
      continue;
    }
    closeList();
    if (!line.trim()) { output.push(""); continue; }
    if (/^@@CODE\d+@@$/.test(line.trim())) { output.push(line.trim()); continue; }
    output.push(`<p>${inlineMarkdown(line)}</p>`);
  }
  closeList();
  let html = output.join("\n");
  codeBlocks.forEach((block, index) => { html = html.replace(`@@CODE${index}@@`, block); });
  return html;
}
async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const body = await response.json();
  if (!response.ok || body.ok === false) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}
function badge(text, kind = "") { return `<span class="badge ${kind}">${escapeHtml(text)}</span>`; }
function toast(message) {
  const node = document.getElementById("toast");
  node.textContent = message;
  node.classList.add("visible");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("visible"), 1800);
}
function nearBottom() {
  const container = document.getElementById("messages");
  return container.scrollHeight - container.scrollTop - container.clientHeight < 160;
}
function scrollLatest(force = false) {
  const container = document.getElementById("messages");
  if (force || state.followLatest || nearBottom()) {
    requestAnimationFrame(() => {
      container.scrollTop = container.scrollHeight;
      document.getElementById("jump-latest").classList.remove("visible");
    });
  } else {
    document.getElementById("jump-latest").classList.add("visible");
  }
}
function scrollToWorking() {
  const node = document.querySelector('.message[data-status="thinking"]');
  if (node) node.scrollIntoView({ behavior: "smooth", block: "center" });
  else scrollLatest(true);
}
function thinkingHtml(message) {
  const progress = message.progress || {};
  const events = progress.events || [];
  const created = message.created_at || new Date().toISOString();
  return `<div class="thinking-card" data-thinking-start="${escapeHtml(created)}">
    <div class="thinking-title"><span class="spinner"></span><span>ARIA is working</span><span class="elapsed">0s</span></div>
    <div class="thinking-stage">${escapeHtml(progress.label || "Preparing the investigation")}</div>
    <div class="thinking-detail">${escapeHtml(progress.detail || "Local models and read-only Splunk evidence controls are running.")}</div>
    <div class="progress-track"><div class="progress-pulse"></div></div>
    <div class="step-list">${events.slice(-8).map(event => `<div class="step ${escapeHtml(event.status || "")}"><span class="step-dot"></span><span><strong>${escapeHtml(event.label || event.stage || "")}</strong>${event.detail ? `<br><span class="small">${escapeHtml(event.detail)}</span>` : ""}</span></div>`).join("")}</div>
  </div>`;
}
function emptyStateHtml() {
  const prompts = [
    ["Meet ARIA", "Who are you and what can you help a SOC analyst do?"],
    ["Explain SPL", "Explain this SPL and identify assumptions, performance concerns and safer improvements:"],
    ["Query Splunk", "Use live Splunk evidence to show what telemetry is available in the last 24 hours."],
    ["Start an investigation", "Help me test a threat hypothesis using live Splunk evidence."],
  ];
  return `<div class="empty"><h1>Your SOC investigation, in one conversation</h1><p>ARIA routes every request through a deterministic control plane, then uses local models and live read-only Splunk evidence only when the selected agent requires them.</p><div class="empty-grid">${prompts.map(([title, prompt]) => `<button class="empty-item starter-prompt" data-prompt="${escapeHtml(prompt)}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(prompt)}</span></button>`).join("")}</div></div>`;
}
function resultHasEvidence(result) {
  if (!result || typeof result !== "object") return false;
  const sources = Array.isArray(result.source_evidence) ? result.source_evidence : [];
  const searches = Array.isArray(result.searches) ? result.searches : [];
  return sources.length > 0 || searches.length > 0 || Boolean(result.finding) || Boolean(result.confidence);
}
function renderMessages(forceBottom = false) {
  const container = document.getElementById("messages");
  const previousTop = container.scrollTop;
  const wasNear = nearBottom();
  const messages = state.chat?.messages || [];
  if (!messages.length) {
    container.innerHTML = emptyStateHtml();
    document.querySelectorAll(".starter-prompt").forEach(button => button.addEventListener("click", () => fillPrompt(button.dataset.prompt || "")));
    return;
  }
  container.innerHTML = messages.map(message => {
    const assistant = message.role === "assistant";
    const meta = [];
    if (message.status === "thinking") meta.push(badge("WORKING", "good"));
    else {
      if (message.capability) meta.push(badge(message.capability));
      if (message.verdict) meta.push(badge(message.verdict, message.verdict.includes("ERROR") ? "danger" : ((message.verdict.includes("INSUFFICIENT") || message.verdict.includes("NO_RELEVANT")) ? "warn" : "good")));
      if (message.confidence !== null && message.confidence !== undefined) meta.push(badge(`${message.confidence}/100 evidence`));
      if (message.duration_seconds !== null && message.duration_seconds !== undefined) meta.push(badge(`${message.duration_seconds}s`));
    }
    const body = message.status === "thinking"
      ? thinkingHtml(message)
      : (assistant ? markdownToHtml(message.content) : `<p>${escapeHtml(message.content).replaceAll("\n", "<br>")}</p>`);
    const tools = assistant && message.status !== "thinking"
      ? `<div class="message-tools"><button class="tool-button copy-answer" data-message-id="${escapeHtml(message.id)}">Copy answer</button>${resultHasEvidence(message.structured_result) ? '<button class="tool-button view-evidence">View evidence</button>' : ""}</div>`
      : "";
    const followups = assistant && message.status !== "thinking" && (message.followups || []).length
      ? `<div class="message-followups"><div class="followup-label">Continue this conversation</div><div class="followup-list">${(message.followups || []).map(action => `<button class="followup-chip" data-followup="${escapeHtml(action)}">${escapeHtml(action)}</button>`).join("")}</div></div>`
      : "";
    return `<article class="message ${assistant ? "assistant" : "user"}" data-message-id="${escapeHtml(message.id)}" data-status="${escapeHtml(message.status || "complete")}"><div class="message-head"><div class="avatar">${assistant ? "AI" : "A"}</div><span class="role">${assistant ? "ARIA" : "Analyst"}</span>${meta.join("")}</div><div class="message-card markdown">${body}${tools}${followups}</div></article>`;
  }).join("");

  document.querySelectorAll(".copy-answer").forEach(button => button.addEventListener("click", () => {
    const message = messages.find(item => item.id === button.dataset.messageId);
    if (navigator.clipboard && message) navigator.clipboard.writeText(message.content || "").then(() => { button.textContent = "Copied"; setTimeout(() => { button.textContent = "Copy answer"; }, 1200); });
  }));
  document.querySelectorAll(".view-evidence").forEach(button => button.addEventListener("click", () => openWorkspace("evidence")));
  document.querySelectorAll(".followup-chip").forEach(button => button.addEventListener("click", () => fillPrompt(button.dataset.followup || "")));

  if (forceBottom || state.followLatest || wasNear) {
    scrollLatest(true);
  } else {
    const maximum = Math.max(0, container.scrollHeight - container.clientHeight);
    container.scrollTop = Math.min(previousTop, maximum);
    document.getElementById("jump-latest").classList.add("visible");
  }
  updateElapsed();
}
function statusText(item) { return item.last_verdict || item.last_capability || ""; }
function renderChats() {
  const query = document.getElementById("chat-search").value.trim().toLowerCase();
  const items = state.chats.filter(item => !query || `${item.title || ""} ${item.last_message || ""} ${statusText(item)}`.toLowerCase().includes(query));
  const list = document.getElementById("chat-list");
  if (!items.length) {
    list.innerHTML = `<div class="small" style="padding:10px">No investigations match this search.</div>`;
    return;
  }
  list.innerHTML = items.map(item => `<div class="chat-row ${item.id === state.chatId ? "active" : ""}" data-row-chat-id="${escapeHtml(item.id)}">
    <button class="chat-main" data-load-chat="${escapeHtml(item.id)}">
      <div class="chat-title-line">${item.pinned ? '<span class="chat-pin">●</span>' : ""}<span class="chat-title">${escapeHtml(item.title || "New investigation")}</span></div>
      <div class="chat-meta"><span>${escapeHtml(item.updated_label || "")}</span><span>${escapeHtml(statusText(item))}</span></div>
    </button>
    <button class="chat-menu-button" data-chat-menu="${escapeHtml(item.id)}" aria-expanded="${state.openChatMenuId === item.id ? "true" : "false"}" aria-label="Investigation options">•••</button>
    ${state.openChatMenuId === item.id ? `<div class="chat-popover" data-chat-popover="${escapeHtml(item.id)}">
      <button data-chat-action="${item.pinned ? "unpin" : "pin"}" data-chat-id="${escapeHtml(item.id)}">${item.pinned ? "Unpin" : "Pin"}</button>
      <button data-chat-action="rename" data-chat-id="${escapeHtml(item.id)}">Rename</button>
      <button data-chat-action="clear" data-chat-id="${escapeHtml(item.id)}">Clear messages</button>
      <button class="danger" data-chat-action="delete" data-chat-id="${escapeHtml(item.id)}">Delete</button>
    </div>` : ""}
  </div>`).join("");

  document.querySelectorAll("[data-load-chat]").forEach(button => button.addEventListener("click", () => loadChat(button.dataset.loadChat)));
  document.querySelectorAll("[data-chat-menu]").forEach(button => button.addEventListener("click", event => {
    event.stopPropagation();
    const id = button.dataset.chatMenu;
    state.openChatMenuId = state.openChatMenuId === id ? null : id;
    renderChats();
  }));
  document.querySelectorAll("[data-chat-action]").forEach(button => button.addEventListener("click", event => {
    event.stopPropagation();
    const item = state.chats.find(chat => chat.id === button.dataset.chatId);
    handleChatAction(button.dataset.chatAction, item);
  }));
}
function workspaceCard(title, body) { return `<div class="workspace-card"><div class="workspace-card-title">${escapeHtml(title)}</div>${body}</div>`; }
function latestAssistantMessage() {
  return [...(state.chat?.messages || [])].reverse().find(message => message.role === "assistant") || null;
}
function renderOverview() {
  const target = document.getElementById("workspace-overview");
  const result = state.chat?.last_result || {};
  const finding = result.finding || {};
  const confidence = result.confidence || {};
  const searches = result.searches || [];
  const latest = latestAssistantMessage();
  const pending = (state.chat?.messages || []).find(message => message.status === "thinking");
  const metrics = `<div class="metric-grid">
    <div class="metric"><div class="metric-label">Status</div><div class="metric-value">${pending ? "Working" : escapeHtml(finding.verdict || latest?.capability || "Ready")}</div></div>
    <div class="metric"><div class="metric-label">Confidence</div><div class="metric-value">${confidence.score !== undefined ? `${escapeHtml(confidence.score)}/100` : "—"}</div></div>
    <div class="metric"><div class="metric-label">Capability</div><div class="metric-value">${escapeHtml(latest?.capability || result.capability || "—")}</div></div>
    <div class="metric"><div class="metric-label">Live searches</div><div class="metric-value">${searches.length}</div></div>
  </div>`;
  const context = `<div class="detail-row"><div class="detail-label">Investigation</div><div class="detail-value">${escapeHtml(state.chat?.title || "New investigation")}</div></div>
    <div class="detail-row"><div class="detail-label">Messages</div><div class="detail-value">${(state.chat?.messages || []).length}</div></div>
    <div class="detail-row"><div class="detail-label">Current route</div><div class="detail-value">${escapeHtml(latest?.route || "Not routed yet")}</div></div>
    <div class="detail-row"><div class="detail-label">Context</div><div class="detail-value">${escapeHtml(state.chat?.context_note || "No active context note.")}</div></div>`;
  const controls = `<div class="detail-row"><div class="detail-label">Splunk</div><div class="detail-value">Live read-only</div></div>
    <div class="detail-row"><div class="detail-label">Models</div><div class="detail-value">Local intent, planning and bounded reasoning</div></div>
    <div class="detail-row"><div class="detail-label">Operational actions</div><div class="detail-value">Human approval required</div></div>`;
  target.innerHTML = workspaceCard("Current investigation", metrics) + workspaceCard("Conversation context", context) + workspaceCard("Controls", controls);
}
function renderEvidence() {
  const panel = document.getElementById("workspace-evidence");
  const result = state.chat?.last_result;
  if (!result) {
    panel.innerHTML = workspaceCard("No completed evidence", '<div class="small">Evidence appears here after a live investigation. Conversational and SPL-explanation requests do not need a Splunk evidence ledger.</div>');
    return;
  }
  const plan = result.plan || {};
  const finding = result.finding || {};
  const confidence = result.confidence || {};
  const sources = result.source_evidence || [];
  const searches = result.searches || [];
  const factors = confidence.factors || [];
  const requirements = plan.requirements || [];
  const claims = [...(finding.supporting_claims || []), ...(finding.contradicting_claims || [])];
  let html = workspaceCard("Finding", `<div class="metric-grid"><div class="metric"><div class="metric-label">Verdict</div><div class="metric-value">${escapeHtml(finding.verdict || "Not produced")}</div></div><div class="metric"><div class="metric-label">Confidence</div><div class="metric-value">${escapeHtml(confidence.score ?? 0)}/100</div></div></div>`);
  if (requirements.length) html += workspaceCard("Requirements", requirements.map(item => `<div class="requirement"><div class="source-name">${escapeHtml(item.requirement_id)} · ${escapeHtml(item.role)} ${item.required ? "· required" : "· optional"}</div><div class="source-reason">${escapeHtml(item.concept)}</div></div>`).join(""));
  if (sources.length) html += workspaceCard("Source qualification", sources.map(source => `<div class="source"><div class="source-name">${badge(source.accepted ? "ACCEPTED" : "REJECTED", source.accepted ? "good" : "danger")} ${escapeHtml(source.index)} / ${escapeHtml(source.sourcetype)}</div><div class="source-reason">Score ${escapeHtml(source.score)} · co-occurrence ${escapeHtml(source.fully_bound_events || 0)}/${escapeHtml(source.sampled_events || 0)}${(source.rejection_reasons || []).length ? ` · ${escapeHtml(source.rejection_reasons.join("; "))}` : ""}</div></div>`).join(""));
  if (searches.length) html += workspaceCard("Read-only execution", searches.map(search => `<div class="search-item"><div class="source-name">${escapeHtml(search.evidence_id)} · ${search.safe ? "safety PASS" : "BLOCKED"}</div><div class="source-reason">${escapeHtml(search.purpose || "")} · ${escapeHtml((search.rows || []).length)} rows</div></div>`).join(""));
  if (claims.length) html += workspaceCard("Evidence-linked claims", claims.map(claim => `<div class="claim"><div class="source-name">${escapeHtml(claim.claim)}</div><div class="source-reason">Evidence: ${escapeHtml((claim.evidence_refs || []).join(", ") || "none")}</div></div>`).join(""));
  if (factors.length) html += workspaceCard("Confidence calculation", factors.map(factor => `<div class="factor"><div class="source-name">${escapeHtml(factor.factor)} · ${Number(factor.points) >= 0 ? "+" : ""}${escapeHtml(factor.points)}</div><div class="source-reason">${escapeHtml(factor.reason)}</div></div>`).join(""));
  panel.innerHTML = html;
}
function renderActions() {
  const target = document.getElementById("workspace-actions");
  const contextual = state.chat?.context_actions || [];
  const analystTools = [
    "Summarise the current investigation and evidence gaps.",
    "Show the exact SPL executed and explain each stage.",
    "Recommend the next highest-value read-only Splunk query.",
    "Turn only validated evidence into a detection candidate.",
    "Create an evidence-aware RBA and ERS recommendation without writing risk events.",
    "Draft an approval-gated TDIR workflow from the current evidence.",
  ];
  const all = [...contextual, ...analystTools].filter((item, index, array) => item && array.findIndex(value => value.toLowerCase() === item.toLowerCase()) === index).slice(0, 10);
  const buttons = all.map(action => `<button class="action-button" data-action-prompt="${escapeHtml(action)}">${escapeHtml(action)}</button>`).join("");
  const management = `<button class="action-button" data-manage-current="rename">Rename investigation</button><button class="action-button" data-manage-current="clear">Clear messages</button><button class="action-button" data-manage-current="delete" style="color:var(--danger)">Delete investigation</button>`;
  target.innerHTML = workspaceCard("Recommended next actions", `<div class="action-list">${buttons || '<div class="small">Actions will appear after ARIA responds.</div>'}</div>`) + workspaceCard("Investigation management", `<div class="action-list">${management}</div>`);
  target.querySelectorAll("[data-action-prompt]").forEach(button => button.addEventListener("click", () => fillPrompt(button.dataset.actionPrompt || "")));
  target.querySelectorAll("[data-manage-current]").forEach(button => button.addEventListener("click", () => handleChatAction(button.dataset.manageCurrent, state.chats.find(item => item.id === state.chatId) || { id: state.chatId, title: state.chat?.title })));
}
function renderActiveJob() {
  const pending = (state.chat?.messages || []).find(message => message.status === "thinking");
  const bar = document.getElementById("active-job-bar");
  if (!pending) { bar.classList.remove("visible"); return; }
  const progress = pending.progress || {};
  document.getElementById("active-job-stage").textContent = progress.label || "ARIA is working";
  const started = Date.parse(pending.created_at || "");
  document.getElementById("active-job-elapsed").textContent = Number.isFinite(started) ? `${Math.max(0, Math.floor((Date.now() - started) / 1000))}s` : "";
  bar.classList.add("visible");
}
function renderWorkspace() { renderOverview(); renderEvidence(); renderActions(); setWorkspaceTab(state.workspaceTab); }
function renderChat(forceBottom = false) {
  document.getElementById("current-title").textContent = state.chat?.title || "New investigation";
  renderMessages(forceBottom);
  renderWorkspace();
  renderActiveJob();
  const pending = (state.chat?.messages || []).find(message => message.status === "thinking" && message.job_id);
  if (pending && !state.currentJob) { state.currentJob = pending.job_id; setBusy(true); pollJob(pending.job_id); }
}
function fillPrompt(value) {
  const input = document.getElementById("prompt");
  input.value = value;
  input.focus();
  if (isCompact()) closeRight();
}
function setWorkspaceTab(tab) {
  state.workspaceTab = tab;
  document.querySelectorAll("[data-workspace-tab]").forEach(button => button.classList.toggle("active", button.dataset.workspaceTab === tab));
  document.querySelectorAll(".workspace-section").forEach(section => section.classList.toggle("active", section.id === `workspace-${tab}`));
}
function syncPanels() {
  const app = document.getElementById("app");
  const left = document.getElementById("left-panel");
  const right = document.getElementById("right-panel");
  if (isCompact()) {
    app.classList.remove("left-collapsed", "right-collapsed");
    left.classList.toggle("open", state.leftOpen);
    right.classList.toggle("open", state.rightOpen);
    document.getElementById("overlay").classList.toggle("open", state.leftOpen || state.rightOpen);
  } else {
    left.classList.remove("open");
    right.classList.remove("open");
    app.classList.toggle("left-collapsed", !state.leftOpen);
    app.classList.toggle("right-collapsed", !state.rightOpen);
    document.getElementById("overlay").classList.remove("open");
  }
}
function toggleLeft() { state.leftOpen = !state.leftOpen; if (isCompact() && state.leftOpen) state.rightOpen = false; syncPanels(); }
function toggleRight() { state.rightOpen = !state.rightOpen; if (isCompact() && state.rightOpen) state.leftOpen = false; syncPanels(); }
function closeLeft() { if (isCompact()) { state.leftOpen = false; syncPanels(); } }
function closeRight() { if (isCompact()) state.rightOpen = false; else state.rightOpen = false; syncPanels(); }
function openWorkspace(tab = "overview") { state.rightOpen = true; setWorkspaceTab(tab); if (isCompact()) state.leftOpen = false; syncPanels(); }
function openModal(mode, item) {
  state.modal = { mode, item };
  const backdrop = document.getElementById("modal-backdrop");
  const title = document.getElementById("modal-title");
  const copy = document.getElementById("modal-copy");
  const input = document.getElementById("modal-input");
  const confirm = document.getElementById("modal-confirm");
  input.classList.add("hidden");
  confirm.className = "modal-button primary";
  if (mode === "rename") {
    title.textContent = "Rename investigation";
    copy.textContent = "Choose a concise name that will help you find this investigation later.";
    input.value = item?.title || "";
    input.classList.remove("hidden");
    confirm.textContent = "Save";
  } else if (mode === "delete") {
    title.textContent = "Delete investigation?";
    copy.textContent = `This permanently removes “${item?.title || "this investigation"}” from ARIA chat history.`;
    confirm.textContent = "Delete";
    confirm.className = "modal-button danger";
  } else {
    title.textContent = "Clear messages?";
    copy.textContent = `This keeps “${item?.title || "this investigation"}” but removes its messages and active context.`;
    confirm.textContent = "Clear";
  }
  backdrop.classList.remove("hidden");
  requestAnimationFrame(() => (mode === "rename" ? input : confirm).focus());
}
function closeModal() { state.modal = null; document.getElementById("modal-backdrop").classList.add("hidden"); }
async function confirmModal() {
  const modal = state.modal;
  if (!modal?.item?.id || state.busy) return;
  if (modal.mode === "rename") {
    const title = document.getElementById("modal-input").value.trim();
    if (!title) return;
    const body = await api(`/api/chats/${encodeURIComponent(modal.item.id)}/rename`, { method: "POST", body: JSON.stringify({ title }) });
    if (modal.item.id === state.chatId) state.chat = body.chat;
    toast("Investigation renamed");
  } else if (modal.mode === "clear") {
    const body = await api(`/api/chats/${encodeURIComponent(modal.item.id)}/clear`, { method: "POST", body: "{}" });
    if (modal.item.id === state.chatId) { state.chat = body.chat; state.followLatest = true; renderChat(true); }
    toast("Investigation cleared");
  } else if (modal.mode === "delete") {
    await api(`/api/chats/${encodeURIComponent(modal.item.id)}/delete`, { method: "POST", body: "{}" });
    toast("Investigation deleted");
    if (modal.item.id === state.chatId) {
      const listing = await api("/api/chats");
      if ((listing.chats || []).length) await loadChat(listing.chats[0].id);
      else await createChat();
    }
  }
  closeModal();
  await refreshChats();
}
async function handleChatAction(action, item) {
  state.openChatMenuId = null;
  renderChats();
  if (!item?.id) return;
  if (action === "rename" || action === "delete" || action === "clear") { openModal(action, item); return; }
  if (action === "pin" || action === "unpin") {
    await api(`/api/chats/${encodeURIComponent(item.id)}/pin`, { method: "POST", body: JSON.stringify({ pinned: action === "pin" }) });
    toast(action === "pin" ? "Investigation pinned" : "Investigation unpinned");
    await refreshChats();
  }
}
async function refreshChats() {
  const body = await api("/api/chats");
  state.chats = body.chats || [];
  renderChats();
}
async function loadChat(id) {
  if (!id) return;
  const body = await api(`/api/chats/${encodeURIComponent(id)}`);
  state.chatId = body.chat.id;
  state.chat = body.chat;
  state.currentJob = null;
  state.followLatest = true;
  renderChat(true);
  await refreshChats();
  closeLeft();
}
async function createChat() {
  if (state.busy && !confirm("ARIA is still working. Start a separate investigation?")) return;
  const body = await api("/api/chats/new", { method: "POST", body: "{}" });
  state.chatId = body.chat.id;
  state.chat = body.chat;
  state.currentJob = null;
  state.followLatest = true;
  renderChat(true);
  await refreshChats();
  closeLeft();
  document.getElementById("prompt").focus();
}
function setBusy(value) {
  state.busy = value;
  document.getElementById("send").disabled = value;
  document.getElementById("prompt").disabled = value;
  document.getElementById("send").textContent = value ? "ARIA working…" : "Send";
  renderActiveJob();
}
async function sendMessage() {
  if (state.busy) return;
  const input = document.getElementById("prompt");
  const message = input.value.trim();
  if (!message) return;
  if (!state.chatId) await createChat();
  state.followLatest = true;
  setBusy(true);
  input.value = "";
  try {
    const body = await api("/api/chat/start", { method: "POST", body: JSON.stringify({ chat_id: state.chatId, message }) });
    state.chat = body.chat;
    state.chatId = body.chat.id;
    state.currentJob = body.job.id;
    renderChat(true);
    scrollToWorking();
    await refreshChats();
    pollJob(body.job.id);
  } catch (error) {
    setBusy(false);
    alert(String(error.message || error));
  }
}
async function pollJob(jobId) {
  if (state.pollTimer) clearTimeout(state.pollTimer);
  try {
    const body = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    if (body.chat && body.chat.id === state.chatId) {
      state.chat = body.chat;
      renderChat(state.followLatest);
    }
    if (body.job.status === "complete" || body.job.status === "error") {
      state.currentJob = null;
      setBusy(false);
      await refreshChats();
      if (state.followLatest) scrollLatest(true);
      else document.getElementById("jump-latest").classList.add("visible");
      document.getElementById("prompt").focus();
      toast(body.job.status === "complete" ? "ARIA response ready" : "ARIA request stopped");
      return;
    }
    state.pollTimer = setTimeout(() => pollJob(jobId), 800);
  } catch (error) {
    state.pollTimer = setTimeout(() => pollJob(jobId), 1600);
  }
}
function updateElapsed() {
  document.querySelectorAll("[data-thinking-start]").forEach(element => {
    const started = Date.parse(element.dataset.thinkingStart);
    const node = element.querySelector(".elapsed");
    if (node && Number.isFinite(started)) node.textContent = `${Math.max(0, Math.floor((Date.now() - started) / 1000))}s`;
  });
  renderActiveJob();
}
async function initialise() {
  syncViewportHeight();
  syncPanels();
  const status = await api("/api/status");
  state.status = status.status;
  document.getElementById("version-badge").textContent = state.status.version || "unknown";
  await refreshChats();
  if (state.chats.length) await loadChat(state.chats[0].id);
  else await createChat();
}

document.getElementById("send").addEventListener("click", sendMessage);
document.getElementById("prompt").addEventListener("keydown", event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); sendMessage(); } });
document.getElementById("new-chat").addEventListener("click", createChat);
document.getElementById("chat-search").addEventListener("input", renderChats);
document.getElementById("toggle-left").addEventListener("click", toggleLeft);
document.getElementById("toggle-right").addEventListener("click", toggleRight);
document.getElementById("close-right").addEventListener("click", closeRight);
document.getElementById("overlay").addEventListener("click", () => { state.leftOpen = false; state.rightOpen = false; syncPanels(); });
document.getElementById("jump-latest").addEventListener("click", () => { state.followLatest = true; scrollLatest(true); });
document.getElementById("view-progress").addEventListener("click", scrollToWorking);
document.getElementById("messages").addEventListener("scroll", () => {
  if (nearBottom()) {
    state.followLatest = true;
    document.getElementById("jump-latest").classList.remove("visible");
  } else {
    state.followLatest = false;
    if (state.busy) document.getElementById("jump-latest").classList.add("visible");
  }
});
document.querySelectorAll("[data-workspace-tab]").forEach(button => button.addEventListener("click", () => setWorkspaceTab(button.dataset.workspaceTab)));
document.getElementById("modal-cancel").addEventListener("click", closeModal);
document.getElementById("modal-confirm").addEventListener("click", confirmModal);
document.getElementById("modal-input").addEventListener("keydown", event => { if (event.key === "Enter") confirmModal(); });
document.getElementById("modal-backdrop").addEventListener("click", event => { if (event.target.id === "modal-backdrop") closeModal(); });
document.getElementById("current-chat-menu").addEventListener("click", () => {
  const item = state.chats.find(chat => chat.id === state.chatId) || { id: state.chatId, title: state.chat?.title || "Current investigation" };
  openWorkspace("actions");
  if (isCompact()) state.rightOpen = true;
  renderActions();
  toast(`Manage “${item.title}” from the Actions panel`);
});
document.addEventListener("click", event => {
  if (!event.target.closest("[data-chat-menu]") && !event.target.closest("[data-chat-popover]")) {
    if (state.openChatMenuId) { state.openChatMenuId = null; renderChats(); }
  }
});
window.addEventListener("resize", () => { syncViewportHeight(); syncPanels(); }, { passive: true });
window.addEventListener("orientationchange", syncViewportHeight, { passive: true });
if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", syncViewportHeight, { passive: true });
  window.visualViewport.addEventListener("scroll", syncViewportHeight, { passive: true });
}
window.matchMedia("(max-width:1000px)").addEventListener("change", () => {
  state.leftOpen = !isCompact();
  state.rightOpen = !isCompact();
  syncPanels();
});
setInterval(updateElapsed, 1000);
initialise().catch(error => alert(String(error.message || error)));
</script>
</body>
</html>
'''


class ARIARequestHandler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(jsonable(payload), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/":
                body = HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/status":
                self.send_json({"ok": True, "status": engine_status()})
                return
            if path == "/api/chats":
                self.send_json({"ok": True, "chats": list_chats()})
                return
            if path.startswith("/api/jobs/"):
                job_id = unquote(path.split("/api/jobs/", 1)[1].strip("/"))
                job = get_job(job_id)
                if not job:
                    self.send_json({"ok": False, "error": "Job not found"}, 404)
                    return
                self.send_json({"ok": True, "job": job, "chat": load_chat(str(job["chat_id"]))})
                return
            if path.startswith("/api/chats/"):
                chat_id = unquote(path.split("/api/chats/", 1)[1].strip("/"))
                self.send_json({"ok": True, "chat": load_chat(chat_id)})
                return
            self.send_json({"ok": False, "error": "Not found"}, 404)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.web_ui.get")
            self.send_json({"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}, 500)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body = self.read_json()
        try:
            if path == "/api/chat/start":
                result = start_chat_job(body.get("chat_id"), body.get("message") or body.get("question") or "")
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if path == "/api/chat":
                result = handle_chat_message(body.get("chat_id"), body.get("message") or body.get("question") or "")
                self.send_json(result, 200 if result.get("ok") else 400)
                return
            if path == "/api/chats/new":
                self.send_json({"ok": True, "chat": new_chat()})
                return
            if path.startswith("/api/chats/") and path.endswith("/clear"):
                chat_id = unquote(path.split("/api/chats/", 1)[1].rsplit("/clear", 1)[0].strip("/"))
                self.send_json({"ok": True, "chat": clear_chat(chat_id)})
                return
            if path.startswith("/api/chats/") and path.endswith("/rename"):
                chat_id = unquote(path.split("/api/chats/", 1)[1].rsplit("/rename", 1)[0].strip("/"))
                self.send_json({"ok": True, "chat": rename_chat(chat_id, body.get("title") or "")})
                return
            if path.startswith("/api/chats/") and path.endswith("/pin"):
                chat_id = unquote(path.split("/api/chats/", 1)[1].rsplit("/pin", 1)[0].strip("/"))
                self.send_json({"ok": True, "chat": set_chat_pinned(chat_id, bool(body.get("pinned")))})
                return
            if path.startswith("/api/chats/") and path.endswith("/delete"):
                chat_id = unquote(path.split("/api/chats/", 1)[1].rsplit("/delete", 1)[0].strip("/"))
                delete_chat(chat_id)
                self.send_json({"ok": True})
                return
            self.send_json({"ok": False, "error": "Not found"}, 404)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.web_ui.post")
            self.send_json({"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}, 500)


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_DESCRIPTION)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8501)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), ARIARequestHandler)
    print(f"{APP_NAME} conversational evidence-first UI listening on http://{args.host}:{args.port}")
    print(f"Version: {read_product_text('product/VERSION')}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
