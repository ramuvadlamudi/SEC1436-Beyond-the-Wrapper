from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"(?i)(password\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(token\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(authorization\s*:\s*)[^\s]+"),
    re.compile(r"(?i)(splunk_password\s*=\s*)[^\s]+"),
]


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    product: str
    version: str
    release_channel: str
    execution_mode: str
    capability: str | None
    route: str | None
    status: str
    prompt_hash: str | None
    prompt_preview: str | None
    answer_hash: str | None
    answer_preview: str | None
    metadata: dict[str, Any]


class AuditLogger:
    def __init__(self) -> None:
        self.enabled = os.getenv("ARIA_AUDIT_ENABLED", "true").lower() == "true"
        self.audit_dir = Path(os.getenv("ARIA_AUDIT_DIR", "data/audit"))
        self.capture_full_text = os.getenv("ARIA_AUDIT_CAPTURE_FULL_TEXT", "false").lower() == "true"
        self.preview_chars = int(os.getenv("ARIA_AUDIT_PREVIEW_CHARS", "500"))

        self.product = self._read_text("product/PRODUCT_NAME", "ARIA")
        self.version = self._read_text("product/VERSION", "1.0.0-preview")
        self.release_channel = self._read_text("product/RELEASE_CHANNEL", "controlled-preview")

    def _read_text(self, path: str, default: str) -> str:
        p = Path(path)
        if not p.exists():
            return default
        return p.read_text().strip() or default

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _hash(self, value: str | None) -> str | None:
        if value is None:
            return None
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    def _redact(self, value: str | None) -> str | None:
        if value is None:
            return None

        redacted = value

        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)

        return redacted

    def _preview(self, value: str | None) -> str | None:
        if value is None:
            return None

        redacted = self._redact(value)

        if self.capture_full_text:
            return redacted

        if len(redacted) <= self.preview_chars:
            return redacted

        return redacted[: self.preview_chars] + "...[truncated]"

    def _audit_file(self) -> Path:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        return self.audit_dir / f"aria-audit-{day}.jsonl"

    def log_interaction(
        self,
        *,
        prompt: str | None,
        answer: str | None,
        capability: str | None,
        route: str | None,
        status: str = "success",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return

        event = AuditEvent(
            timestamp=self._now(),
            event_type="interaction",
            product=self.product,
            version=self.version,
            release_channel=self.release_channel,
            execution_mode="read_only",
            capability=capability,
            route=route,
            status=status,
            prompt_hash=self._hash(prompt),
            prompt_preview=self._preview(prompt),
            answer_hash=self._hash(answer),
            answer_preview=self._preview(answer),
            metadata=metadata or {},
        )

        with self._audit_file().open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), ensure_ascii=False, sort_keys=True) + "\n")

    def log_system_event(
        self,
        *,
        event_type: str,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return

        event = AuditEvent(
            timestamp=self._now(),
            event_type=event_type,
            product=self.product,
            version=self.version,
            release_channel=self.release_channel,
            execution_mode="read_only",
            capability=None,
            route=None,
            status=status,
            prompt_hash=None,
            prompt_preview=None,
            answer_hash=None,
            answer_preview=None,
            metadata=metadata or {},
        )

        with self._audit_file().open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), ensure_ascii=False, sort_keys=True) + "\n")


audit_logger = AuditLogger()
