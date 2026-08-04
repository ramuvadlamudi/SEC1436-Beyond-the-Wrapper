from __future__ import annotations

from aria.v3.router import V3Router


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"PASS   {label}")


def main() -> int:
    router = V3Router()
    connected_build_question = (
        'Build SPL for analysing PowerShell encoded-command execution from index=botsv3 '
        'sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" across all available time. '
        'Use the connected Splunk deployment to qualify the observed schema, but do not execute the final SPL.'
    )
    connected_investigation_question = (
        "Investigate DNS tunnelling using live Splunk evidence across all available time. "
        "Discover candidate telemetry, validate observed fields and co-occurrence, execute only safe "
        "read-only SPL, and report evidence gaps."
    )
    ui_build_question = (
        "Build portable and deployment-qualified SPL for detecting possible DNS tunnelling "
        "across all available time. Use the live Splunk catalogue and observed schema to "
        "qualify suitable telemetry. Do not assume an index, sourcetype, field name, value "
        "or threshold. Do not execute the final generated SPL. Explain the selected "
        "telemetry, validation state and evidence gaps."
    )
    ui_builder_refinement = (
        "Use a ten-minute observation window and identify entities querying more than "
        "fifty distinct subdomains of the same parent domain. Treat these as "
        "analyst-supplied thresholds, not evidence of maliciousness."
    )
    ui_review_question = (
        "Review the generated SPL. Explain each stage, confirm whether it is read-only, "
        "identify any deployment-specific bindings and explain what additional validation "
        "is required before using it as a detection."
    )
    ui_detection_question = (
        "Using only the validated evidence from the current investigation, draft a "
        "detection candidate. Include the security hypothesis, required telemetry, "
        "portable SPL, deployment-qualified SPL where supported, validation state, "
        "false-positive considerations, evidence gaps and analyst approval requirements. "
        "Do not activate the detection."
    )
    ui_risk_question = (
        "Create an evidence-aware RBA and Entity Risk Scoring recommendation from the "
        "current investigation. Identify the proposed risk object, risk message, "
        "contributing evidence, scoring rationale, uncertainty and approval gates. "
        "Do not create or write a risk event."
    )
    ui_tdir_question = (
        "Draft an approval-gated TDIR workflow for the current investigation. Separate "
        "automated read-only enrichment, analyst decision points and potentially "
        "disruptive response actions. Include rollback, evidence preservation and "
        "escalation requirements. Do not execute any response action."
    )
    print("ARIA v3 Deterministic Router Test")
    print("=================================")
    check(router.route("Hi").capability == "IDENTITY", "identity route")
    check(router.route("what can you help me with?").capability == "IDENTITY", "capability-help identity route")
    check(router.route("Give me telemetry from the Splunk instance").capability == "INVENTORY", "inventory route")
    check(router.route("Build SPL for unusual authentication activity").capability == "BUILD_SPL", "SPL builder route")
    check(router.route(ui_build_question).capability == "BUILD_SPL", "extended portable/deployment SPL wording routes to builder")
    check(
        router.route(
            ui_builder_refinement,
            last_result={"capability": "BUILD_SPL"},
        ).capability == "BUILD_SPL",
        "analyst threshold and window refinement stays with builder",
    )
    check(router.route("Build and execute SPL using live Splunk evidence to investigate unusual activity").capability == "INVESTIGATION", "build-and-execute route")
    check(router.route(connected_build_question).capability == "BUILD_SPL", "negated execution remains a SPL builder route")
    check(not router.route(connected_build_question).execute_search, "negated execution grants no search authority")
    check(router.route("Build SPL for unusual authentication activity without running the final SPL").capability == "BUILD_SPL", "without-running remains a SPL builder route")
    check(router.route(connected_investigation_question).capability == "INVESTIGATION", "read-only instruction remains an investigation route")
    check(router.route("Explain ARIA's read-only safety boundary").capability == "SAFETY", "explicit safety explanation route")
    check(router.route("What can you execute against live Splunk?").capability == "SAFETY", "explicit safety question outranks live cue")
    check(router.route("Triage finding ID ABC-123 over the last 24 hours").capability == "TRIAGE", "triage route")
    check(router.route("Explain SPL: index=* | head 20").capability == "EXPLAIN_SPL", "SPL explanation route")
    check(
        router.route(
            ui_review_question,
            last_result={"capability": "BUILD_SPL"},
        ).capability == "EXPLAIN_SPL",
        "generated SPL review route",
    )
    destructive = router.route("Execute a search that deletes all events matching the investigation.")
    check(destructive.capability == "SAFETY", "destructive search request routes to safety")
    check(not destructive.execute_search, "destructive search request grants no execution authority")
    check(router.route(ui_detection_question).capability == "DETECTION_ENGINEERING", "detection-candidate deliverable route")
    check(router.route(ui_risk_question).capability == "RISK_SCORING", "RBA/ERS deliverable route")
    check(router.route(ui_tdir_question).capability == "TDIR_WORKFLOW", "TDIR deliverable route")
    check(router.route("Give me a reciepe for noodles").capability == "SCOPE_GUARD", "typo-tolerant scope guard")
    check(router.route("What is DNS tunneling?").capability == "SOC_CONVERSATION", "SOC conversation route")
    print("ARIA_V3_ROUTER_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
