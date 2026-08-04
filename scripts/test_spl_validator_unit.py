from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aria.spl_validator as spl_validator_module


ROOT = Path(__file__).resolve().parents[1]


def _safe_value(result: Any) -> bool | None:
    if result is None:
        return None

    if isinstance(result, dict):
        for key in ("safe", "is_safe", "allowed", "valid", "ok"):
            if key in result:
                return bool(result[key])

    for attr in ("safe", "is_safe", "allowed", "valid", "ok"):
        if hasattr(result, attr):
            return bool(getattr(result, attr))

    if isinstance(result, tuple) and result and isinstance(result[0], bool):
        return bool(result[0])

    if isinstance(result, bool):
        return bool(result)

    return None


def _errors(result: Any) -> list[str]:
    if isinstance(result, dict):
        return list(result.get("errors", []))

    value = getattr(result, "errors", [])

    if isinstance(value, list):
        return value

    return []


def _load_policy() -> dict:
    policy = json.loads((ROOT / "product" / "safety_policy.json").read_text())
    return policy.get("spl_read_only_policy", {})


def _module_validate(spl: str):
    return spl_validator_module.validate(spl)


def _live_instance_validate(candidate):
    return spl_validator_module.spl_validator.validate(candidate)


def test_hunt_candidate_shape() -> None:
    spl = (
        "search index={analyst_selected_index} "
        "sourcetype={analyst_selected_sourcetype} "
        "earliest={time_window} latest=now\n"
        "| eval aria_entity=coalesce({entity_field}, \"unknown\")\n"
        "| eval aria_activity=coalesce({activity_field}, \"unknown\")\n"
        "| bin _time span=15m\n"
        "| stats count as event_count values(aria_activity) as observed_activities by _time aria_entity\n"
        "| where event_count > 1\n"
        "| sort - event_count\n"
        "| head 20"
    )

    result = _live_instance_validate({"spl": spl})

    if result is None:
        raise AssertionError("Live validator returned None for hunt candidate SPL")


def test_exploratory_shape_no_stats_does_not_crash() -> None:
    spl = (
        "search index={analyst_selected_index} "
        "sourcetype={analyst_selected_sourcetype} "
        "earliest={time_window} latest=now\n"
        "| head 100\n"
        "| table _time index sourcetype host source _raw"
    )

    result = _live_instance_validate({"spl": spl})

    if result is None:
        raise AssertionError("Live validator returned None for exploratory SPL")

    if _safe_value(result) is False:
        raise AssertionError(f"Exploratory read-only SPL should not be blocked: {_errors(result)}")


def test_policy_loaded_by_live_instance() -> None:
    result = _live_instance_validate({"spl": "search * | head 1"})

    if not bool(result.get("policy_loaded")):
        raise AssertionError("Live class-based validator did not load product/safety_policy.json")


def test_policy_loaded_by_module_validate() -> None:
    result = _module_validate("search * | head 1")

    if not bool(result.get("policy_loaded")):
        raise AssertionError("Module-level validate() did not load product/safety_policy.json")


def test_live_instance_blocks_all_policy_commands() -> None:
    policy = _load_policy()
    commands = list(policy.get("blocked_commands", []))

    if not commands:
        raise AssertionError("No blocked_commands found in product/safety_policy.json")

    failures: list[str] = []

    for command in commands:
        spl = f"search * | {command}"
        result = _live_instance_validate({"spl": spl})
        safe = _safe_value(result)

        if safe is not False:
            failures.append(command)

    if failures:
        raise AssertionError(f"Live validator did not block policy commands: {failures}")


def test_module_validate_blocks_all_policy_commands() -> None:
    policy = _load_policy()
    commands = list(policy.get("blocked_commands", []))

    if not commands:
        raise AssertionError("No blocked_commands found in product/safety_policy.json")

    failures: list[str] = []

    for command in commands:
        spl = f"search * | {command}"
        result = _module_validate(spl)
        safe = _safe_value(result)

        if safe is not False:
            failures.append(command)

    if failures:
        raise AssertionError(f"Module validate() did not block policy commands: {failures}")


def test_live_instance_blocks_policy_functions_or_actions() -> None:
    policy = _load_policy()
    actions = list(policy.get("blocked_functions_or_actions", []))

    failures: list[str] = []

    for action in actions:
        spl = f"search * | eval marker={action}(\"example\")"
        result = _live_instance_validate({"spl": spl})
        safe = _safe_value(result)

        if safe is not False:
            failures.append(action)

    if failures:
        raise AssertionError(f"Live validator did not block policy functions/actions: {failures}")


def test_specific_regression_sendalert_mcollect_notable() -> None:
    samples = {
        "sendalert": "search * | sendalert",
        "mcollect": "search * | mcollect",
        "notable": "search * | eval marker=notable(\"example\")",
    }

    failures: list[str] = []

    for name, spl in samples.items():
        result = _live_instance_validate({"spl": spl})
        safe = _safe_value(result)

        if safe is not False:
            failures.append(name)

    if failures:
        raise AssertionError(f"Specific policy regressions not blocked: {failures}")


def main() -> int:
    print("ARIA SPL Validator Unit Test")
    print("============================")

    tests = (
        test_hunt_candidate_shape,
        test_exploratory_shape_no_stats_does_not_crash,
        test_policy_loaded_by_live_instance,
        test_policy_loaded_by_module_validate,
        test_live_instance_blocks_all_policy_commands,
        test_module_validate_blocks_all_policy_commands,
        test_live_instance_blocks_policy_functions_or_actions,
        test_specific_regression_sendalert_mcollect_notable,
    )

    failures = 0

    for test in tests:
        try:
            test()
            print(f"PASS   {test.__name__}")
        except Exception as exc:
            failures += 1
            print(f"FAIL   {test.__name__}: {repr(exc)}")

    print()

    if failures:
        print(f"ARIA_SPL_VALIDATOR_UNIT_TEST=FAIL failures={failures}")
        return 1

    print("ARIA_SPL_VALIDATOR_UNIT_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
