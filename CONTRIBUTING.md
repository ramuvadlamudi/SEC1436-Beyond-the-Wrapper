# Contributing

ARIA is currently a controlled-preview project. Contributions should preserve its air-gapped, evidence-first and read-only boundaries.

## Before opening a change

- Do not include customer telemetry, credentials, hostnames, private addresses, audit logs or screenshots containing sensitive data.
- Do not hardcode indexes, sourcetypes, fields, event identifiers, entities, values, thresholds or use-case mappings in runtime Python.
- Keep routing and SPL safety deterministic.
- Keep write-capable Splunk, SOAR and response actions outside this runtime.
- Add source attribution for public-framework reference cards.
- Keep Pattern A examples bounded, placeholder-based and explicit that model output is untrusted.
- Keep Pattern C material labelled experimental until a separately accepted implementation exists.

## Development workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
python validate_v3_acceptance.py --skip-live
```

Changes to connected behaviour should also pass `scripts/live_v3_acceptance.py` in an approved test deployment.

## Pull requests

Describe:

- the problem and safety impact;
- the change and affected agent contract;
- tests added or updated;
- connected evidence used, with sensitive values removed;
- documentation or migration impact.

All package gates, the hardcoding audit, the release artifact audit and the GitHub publication audit must pass.

## Reference cards

Reference cards are generic data in `product/knowledge/reference_cards.json`. New cards must:

- describe a public security or Splunk concept;
- use authoritative primary sources;
- include exact required phrases and all six SOC response sections;
- avoid customer-specific telemetry mappings or detection claims;
- include regression coverage in `scripts/test_v3_reference_knowledge.py`.
