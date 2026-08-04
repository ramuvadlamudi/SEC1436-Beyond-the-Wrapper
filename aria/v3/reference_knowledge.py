from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aria.suppressed_exception_logger import log_suppressed_exception
from aria.v3.utils import compact_text, normalise


REQUIRED_SECTIONS = (
    "Exact definition",
    "Scope and structure",
    "Relationship to adjacent concepts",
    "SOC operational use",
    "Splunk application",
    "Limitations and validation",
)


@dataclass(frozen=True)
class ReferenceMatch:
    cards: tuple[dict[str, Any], ...]

    @property
    def primary(self) -> dict[str, Any]:
        return self.cards[0]

    @property
    def card_ids(self) -> list[str]:
        return [str(card.get("id") or "") for card in self.cards]

    @property
    def source_urls(self) -> list[str]:
        output: list[str] = []
        for card in self.cards:
            for source in card.get("sources") or []:
                url = str(source.get("url") or "").strip()
                if url and url not in output:
                    output.append(url)
        return output

    def prompt_payload(self) -> str:
        payload = {
            "grounding_rule": (
                "Treat exact names, expansions, distinctions and source URLs as "
                "authoritative local reference facts. Do not invent framework "
                "tactics, techniques, identifiers or claims not contained here."
            ),
            "cards": [
                {
                    "id": card.get("id"),
                    "canonical_name": card.get("canonical_name"),
                    "required_phrases": card.get("required_phrases") or [],
                    "summary": card.get("summary"),
                    "sections": card.get("sections") or {},
                    "sources": card.get("sources") or [],
                }
                for card in self.cards
            ],
        }
        return compact_text(json.dumps(payload, ensure_ascii=False), 9000)


class LocalReferenceStore:
    """Generic, source-attributed reference grounding for air-gapped conversation.

    The runtime has no topic-specific branch. New public framework references can
    be added as data cards without changing routing, Splunk access or Python code.
    """

    def __init__(self, path: Path | None = None) -> None:
        default = (
            Path(__file__).resolve().parents[2]
            / "product"
            / "knowledge"
            / "reference_cards.json"
        )
        configured = str(os.getenv("ARIA_V3_REFERENCE_CARDS_PATH") or "").strip()
        self.path = path or (Path(configured).expanduser() if configured else default)
        self._cards = self._load()

    def _load(self) -> tuple[dict[str, Any], ...]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            cards = payload.get("cards") or []
            if not isinstance(cards, list):
                raise ValueError("reference_cards.json cards must be a list")
            validated: list[dict[str, Any]] = []
            for card in cards:
                if not isinstance(card, dict):
                    raise ValueError("reference card must be an object")
                required = ("id", "canonical_name", "aliases", "sections", "sources")
                if any(not card.get(field) for field in required):
                    raise ValueError(f"reference card missing required field: {card}")
                sections = card.get("sections") or {}
                if any(not str(sections.get(section) or "").strip() for section in REQUIRED_SECTIONS):
                    raise ValueError(f"reference card {card.get('id')} is missing a required section")
                validated.append(card)
            return tuple(validated)
        except Exception as exc:
            log_suppressed_exception(exc, component="aria.v3.reference_knowledge")
            return ()

    def match(self, question: str, context: str = "") -> ReferenceMatch | None:
        current = normalise(question)
        prior = normalise(context)
        ranked: list[tuple[int, str, dict[str, Any]]] = []
        for card in self._cards:
            score = 0
            aliases = [
                normalise(alias)
                for alias in card.get("aliases") or []
                if str(alias or "").strip()
            ]
            for alias in aliases:
                if alias and alias in current:
                    score = max(score, 100 + len(alias))
                elif alias and alias in prior:
                    score = max(score, 20 + len(alias))
            if score:
                ranked.append((score, str(card.get("id") or ""), card))
        if not ranked:
            return None
        ranked.sort(key=lambda item: (-item[0], item[1]))
        best_score = ranked[0][0]
        selected = [
            card
            for score, _, card in ranked
            if score >= best_score - 10
        ][:2]
        return ReferenceMatch(cards=tuple(selected))

    @staticmethod
    def validate_answer(answer: str, match: ReferenceMatch) -> tuple[bool, str]:
        text = str(answer or "")
        lowered = normalise(text)
        primary = match.primary
        for phrase in primary.get("required_phrases") or []:
            if normalise(phrase) not in lowered:
                return False, f"grounded answer omitted required reference phrase: {phrase}"
        if not re.search(r"(?im)^###\s+Authoritative local references\s*$", text):
            return False, "grounded answer omitted the authoritative local references section"
        if not any(url in text for url in match.source_urls):
            return False, "grounded answer omitted every authoritative source URL"
        return True, ""

    @staticmethod
    def render(match: ReferenceMatch) -> str:
        primary = match.primary
        sections = primary.get("sections") or {}
        output: list[str] = []
        for section in REQUIRED_SECTIONS:
            output.extend([f"### {section}", "", str(sections.get(section) or "").strip(), ""])
        output.extend(["### Authoritative local references", ""])
        for source in primary.get("sources") or []:
            title = str(source.get("title") or "Reference").strip()
            publisher = str(source.get("publisher") or "").strip()
            url = str(source.get("url") or "").strip()
            verified = str(source.get("verified_on") or "").strip()
            detail = " · ".join(
                item
                for item in (
                    publisher,
                    f"locally verified {verified}" if verified else "",
                )
                if item
            )
            output.append(f"- [{title}]({url})" + (f" — {detail}" if detail else ""))
        return "\n".join(output).strip()


__all__ = ["LocalReferenceStore", "ReferenceMatch", "REQUIRED_SECTIONS"]
