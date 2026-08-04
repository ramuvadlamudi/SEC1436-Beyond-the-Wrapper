# Troubleshooting

## UI is not reachable

1. Confirm the process or service is running.
2. Confirm `ARIA_PRODUCT_HOST` and `ARIA_PRODUCT_PORT` match the approved interface.
3. Check the local host firewall and any approved reverse proxy.
4. Run `python aria_health.py` on the ARIA server.
5. Review service logs locally; remove sensitive values before sharing them.

Do not expose the UI on an untrusted interface without authentication, TLS and approval.

## Ollama is unavailable or slow

- Confirm `OLLAMA_URL` is reachable from the ARIA server.
- Confirm configured models exist locally.
- Pre-warm the selected model before a demonstration.
- Prefer a smaller fast model on CPU-only infrastructure.
- Increase `OLLAMA_TIMEOUT` only within the approved latency budget.

Routing, inventory and safety should remain deterministic. A timeout must not grant additional execution authority.

## Splunk catalogue is visible but raw events are unavailable

- Confirm the account can search the approved indexes, not only view metadata.
- Check role search filters, time limits and index restrictions.
- Use an explicit analyst-approved time range.
- Treat the condition as an access/evidence gap; do not invent fields or reuse cached customer mappings.

## BUILD_SPL returns `NO_SCHEMA_QUALIFIED_SPL`

This is an expected evidence-first outcome when the connected source cannot prove every required measurement and grouping field.

- Review the portable SPL placeholders.
- Review observed field-binding gaps.
- Select an explicit source only when the analyst knows it is appropriate.
- Refine the requested observable concepts.

Do not weaken the analyst's metric or map semantically unrelated fields merely to produce deployment SPL.

## Investigation returns `INSUFFICIENT_EVIDENCE`

- Check whether the qualified search returned rows.
- Confirm required fields are populated in the executed events.
- Review the selected time range.
- Add an entity, value or comparison objective if the original hypothesis is too broad.
- Seek corroborating telemetry.

Event count alone is not proof of maliciousness.

## Triage confidence is zero

Triage needs a finding/entity or current structured Investigation evidence. Continue from the Investigation in the same conversation or provide an analyst-supplied finding reference.

## GitHub validation fails

Run locally from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
python validate_v3_acceptance.py --skip-live
```

Do not bypass a failing safety, hardcoding, source-sanitization or architecture gate. Fix the identified issue and rerun the entire package suite.
