from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class ValidationResult(dict):
    """Dictionary result with attribute access for backward compatibility."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_policy() -> dict[str, Any]:
    path = _project_root() / "product" / "safety_policy.json"
    try:
        product_policy = json.loads(path.read_text(encoding="utf-8"))
        spl_policy = product_policy.get("spl_read_only_policy", {})
        return {
            "policy_loaded": True,
            "policy_error": "",
            "blocked_commands": list(spl_policy.get("blocked_commands", [])),
            "blocked_functions_or_actions": list(
                spl_policy.get("blocked_functions_or_actions", [])
            ),
            "default_if_policy_missing": spl_policy.get(
                "default_if_policy_missing", "fail_closed"
            ),
        }
    except Exception as exc:
        return {
            "policy_loaded": False,
            "policy_error": f"{exc.__class__.__name__}: {exc}",
            "blocked_commands": [],
            "blocked_functions_or_actions": [],
            "default_if_policy_missing": "fail_closed",
        }


def _extract_spl(candidate: Any) -> str:
    if candidate is None:
        return ""
    if isinstance(candidate, str):
        return candidate.strip()
    preferred = (
        "spl",
        "search",
        "query",
        "compiled_spl",
        "compiled_search",
        "search_string",
        "generated_spl",
        "final_spl",
    )
    if isinstance(candidate, dict):
        for key in preferred:
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in candidate.values():
            if isinstance(value, str) and ("|" in value or "search" in value.lower()):
                return value.strip()
        return ""
    for attr in preferred:
        value = getattr(candidate, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return str(candidate).strip()


def _has_pipeline_command(spl: str, command: str) -> bool:
    command = str(command or "").strip()
    if not command:
        return False
    return bool(re.search(r"(?im)(^|\|)\s*" + re.escape(command) + r"\b", spl))


def _has_function_or_action(spl: str, action: str) -> bool:
    action = str(action or "").strip()
    if not action:
        return False
    return bool(re.search(r"(?im)\b" + re.escape(action) + r"\s*\(", spl))


class StaticSPLValidator:
    """One policy-backed read-only SPL validator used by every live call path."""

    def validate(self, candidate: Any, *args: Any, **kwargs: Any) -> ValidationResult:
        spl = _extract_spl(candidate)
        lowered = spl.lower()
        policy = _load_policy()
        errors: list[str] = []
        warnings: list[str] = []
        blocked_commands: list[str] = []
        blocked_actions: list[str] = []

        if not spl:
            errors.append("SPL is empty.")

        if not policy["policy_loaded"]:
            if policy["default_if_policy_missing"] == "fail_closed":
                errors.append("SPL safety policy could not be loaded; failing closed.")
            else:
                warnings.append("SPL safety policy could not be loaded.")

        for command in policy["blocked_commands"]:
            if _has_pipeline_command(lowered, command):
                blocked_commands.append(str(command))
                errors.append(f"Blocked SPL command by read-only policy: {command}")

        for action in policy["blocked_functions_or_actions"]:
            if _has_function_or_action(lowered, action):
                blocked_actions.append(str(action))
                errors.append(f"Blocked SPL function/action by read-only policy: {action}")

        if isinstance(candidate, dict):
            expected_index = str(candidate.get("index") or "").strip()
            expected_sourcetype = str(candidate.get("sourcetype") or "").strip()
            if expected_index and f'index="{expected_index}"' not in spl:
                errors.append("SPL does not contain the validated index binding.")
            if expected_sourcetype and f'sourcetype="{expected_sourcetype}"' not in spl:
                errors.append("SPL does not contain the validated sourcetype binding.")

        if "| stats " not in lowered:
            warnings.append("SPL does not aggregate results with stats.")
        if "| head " not in lowered and "| stats " not in lowered:
            warnings.append("SPL has no explicit result limiter or aggregation.")

        safe = not errors
        return ValidationResult(
            {
                "safe": safe,
                "is_safe": safe,
                "valid": safe,
                "allowed": safe,
                "ok": safe,
                "errors": errors,
                "warnings": warnings,
                "blocked_commands": blocked_commands,
                "blocked_functions_or_actions": blocked_actions,
                "policy_loaded": bool(policy["policy_loaded"]),
                "policy_error": policy["policy_error"],
                "policy_source": "product/safety_policy.json",
                "spl_preview": spl[:500],
            }
        )


spl_validator = StaticSPLValidator()


def validate(candidate: Any, *args: Any, **kwargs: Any) -> ValidationResult:
    return spl_validator.validate(candidate, *args, **kwargs)


def validate_spl(candidate: Any, *args: Any, **kwargs: Any) -> ValidationResult:
    return validate(candidate, *args, **kwargs)


def validate_search(candidate: Any, *args: Any, **kwargs: Any) -> ValidationResult:
    return validate(candidate, *args, **kwargs)


def validate_readonly_spl(candidate: Any, *args: Any, **kwargs: Any) -> ValidationResult:
    return validate(candidate, *args, **kwargs)


def validate_compiled_spl(candidate: Any, *args: Any, **kwargs: Any) -> ValidationResult:
    return validate(candidate, *args, **kwargs)
