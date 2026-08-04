# Configuration

Copy `.env.example` to `.env` and configure local endpoints. `.env` is excluded from source control and must never be uploaded to GitHub.

## Splunk

| Variable | Purpose |
|---|---|
| `SPLUNK_URL` | Splunk management/search API URL |
| `SPLUNK_USERNAME` | Dedicated least-privilege read-only account |
| `SPLUNK_PASSWORD` | Password supplied through the approved local secret process |
| `SPLUNK_VERIFY_SSL` | Keep `true` with a trusted certificate |
| `SPLUNK_TIMEOUT` | Maximum request duration for bounded operations |

The account should have only the search and metadata permissions needed for intended indexes. RC11 does not require write, alert, notable, risk or SOAR permissions.

## Ollama

| Variable | Purpose |
|---|---|
| `OLLAMA_URL` | Local Ollama API endpoint |
| `OLLAMA_FAST_MODEL` | Low-latency model for routing-adjacent bounded tasks and drafting |
| `OLLAMA_REASONING_MODEL` | Model used for deeper bounded explanation or reasoning |
| `OLLAMA_EMBEDDING_MODEL` | Local embedding model for semantic field matching |
| `OLLAMA_TIMEOUT` | Model request deadline |
| `OLLAMA_KEEP_ALIVE` | Ollama model keep-alive policy |

Routing and safety remain deterministic even when Ollama is unavailable.

## ARIA services

| Variable | Purpose |
|---|---|
| `ARIA_LLM_GATEWAY_HOST` | Local model gateway bind address |
| `ARIA_LLM_GATEWAY_PORT` | Local model gateway port |
| `ARIA_PRODUCT_HOST` | Analyst workspace bind address |
| `ARIA_PRODUCT_PORT` | Analyst workspace port |
| `ARIA_AUDIT_ENABLED` | Enables structured audit output |
| `ARIA_AUDIT_CAPTURE_FULL_TEXT` | Keep `false` unless explicitly approved |
| `ARIA_AUDIT_DIR` | Runtime audit directory; excluded from GitHub |

## Offline framework knowledge

ARIA includes source-attributed public framework cards in `product/knowledge/reference_cards.json`. An approved replacement path can be set with:

```text
ARIA_V3_REFERENCE_CARDS_PATH=/approved/local/path/reference_cards.json
```

Reference cards must contain public framework facts and citations only. Do not add customer telemetry mappings, credentials, internal incident content or private identifiers.

## Example template

Use the reserved example endpoints in `.env.example` as placeholders only. Replace them locally after installation:

```text
SPLUNK_URL=https://splunk.example.invalid:8089
OLLAMA_URL=http://ollama.example.invalid:11434
```

Never place real endpoints or credentials in issues, screenshots, commits or acceptance reports intended for publication.
