from __future__ import annotations

import json
import os
import traceback

from aria.copilot.engine import copilot_engine


BANNER = """
========================================================================
ARIA — EVIDENCE-FIRST AIR-GAPPED SOC COPILOT
Pattern B — Natural Language + Local LLM + Live Splunk Evidence
========================================================================
"""

HELP_TEXT = """
Commands:
  exit        Quit ARIA
  help        Show this help
  debug       Show structured result after the analyst answer
  analyst     Show analyst answer only

Examples:
  What data is available in Splunk?
  Explain this SPL: <paste SPL>
  Find suspicious activity using live Splunk evidence.
  Investigate <analyst-supplied entity>.
  Build a detection candidate from validated evidence.
  Create an evidence-aware RBA/ERS recommendation.
  Draft an approval-gated TDIR workflow.
"""


def main() -> None:
    output_mode = os.getenv("ARIA_OUTPUT_MODE", "analyst").strip().lower()
    if output_mode not in {"analyst", "debug"}:
        output_mode = "analyst"

    history: list[dict[str, str]] = []
    last_result = None

    print(BANNER)
    print("Type 'help' for examples and 'exit' to quit.\n")

    while True:
        try:
            question = input("Analyst > ").strip()
            if not question:
                continue

            command = question.lower()
            if command in {"exit", "quit"}:
                print("Goodbye.")
                break
            if command == "help":
                print(HELP_TEXT)
                continue
            if command == "debug":
                output_mode = "debug"
                print("Output mode set to debug.")
                continue
            if command == "analyst":
                output_mode = "analyst"
                print("Output mode set to analyst.")
                continue

            result = copilot_engine.invoke(
                question,
                history=history,
                last_result=last_result,
            )
            print("\n" + "=" * 72)
            print("ARIA")
            print("=" * 72 + "\n")
            print(result.answer)

            if output_mode == "debug":
                print("\n" + "-" * 72)
                print("STRUCTURED RESULT")
                print("-" * 72)
                print(json.dumps(result.model_dump(), indent=2, default=str))

            history.append({"role": "user", "content": question})
            history.append({"role": "assistant", "content": result.answer})
            history = history[-12:]
            last_result = result.model_dump()

        except KeyboardInterrupt:
            print("\nGoodbye.")
            break
        except Exception as exc:
            print(f"\nARIA ERROR: {exc.__class__.__name__}: {exc}")
            if output_mode == "debug":
                traceback.print_exc()


if __name__ == "__main__":
    main()
