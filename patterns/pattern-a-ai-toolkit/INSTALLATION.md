# Pattern A installation and connection

## Prerequisites

- Splunk Enterprise with a compatible Splunk AI Toolkit and Python for Scientific Computing add-on.
- An AI Toolkit release that contains the `ai` command and Ollama connector. The command was introduced in the 5.6 release line; use the current compatibility matrix for the exact Splunk and PSC versions.
- An approved Ollama endpoint reachable from the Splunk search tier inside the enclave.
- A model imported through the organisation's offline software/model supply-chain process.
- TLS or an equivalent protected enclave transport appropriate to the deployment.
- A least-privilege Splunk role for the demonstration data and `apply_ai_commander_command` capability.

Keep connection-management capabilities such as `edit_ai_commander_config` and `list_ai_commander_config` with an administrator unless the operator genuinely needs them. Do not grant a broad administrative role merely to run a demonstration search.

## Air-gapped preparation

1. Obtain the approved AI Toolkit, PSC add-on and model artefacts through a connected staging process.
2. Record source, version, licence, checksum, SBOM where available and vulnerability-scan result.
3. Transfer artefacts through the approved media or cross-domain process.
4. Verify the checksum again inside the enclave.
5. Install the Splunk apps according to the version-specific documentation.
6. Import the approved Ollama model without enabling an outbound dependency.

This repository deliberately contains no model weights, Splunk packages, credentials, tokens or private endpoints.

## Configure the LLM connection

In the AI Toolkit:

1. Open **Connections**.
2. Create an **LLM** connection.
3. Select **Ollama**.
4. Enter the enclave-local endpoint and an approved default model.
5. Test the connection.
6. Save it using Splunk-managed secret storage where credentials are required.

Names and fields vary by AI Toolkit release. Follow the documentation matching the installed version.

## Minimal smoke test

Use a non-sensitive generated row and explicitly set the provider and approved model:

```spl
| makeresults
| eval test_value="ARIA_LOCAL_LLM_TEST"
| ai prompt="Return exactly LOCAL_LLM_OK for this connectivity test: {test_value}" provider=Ollama model=<LOCAL_MODEL>
| fields ai_result_*
```

Replace `<LOCAL_MODEL>` before execution. Expected outcome: one returned model-result field containing `LOCAL_LLM_OK`. This checks connectivity only; it does not validate security accuracy, grounding or production performance.

## Operational readiness checks

- Confirm the request never leaves the approved network boundary.
- Confirm the intended model is selected and pre-warmed.
- Set a maximum input-row count, time range and field allowlist.
- Measure timeout, concurrency, CPU/GPU use and search-head impact.
- Record failure behaviour when Ollama is unavailable or slow.
- Confirm ordinary users cannot edit provider endpoints or secrets.
- Confirm generated answers are not automatically written to a notable, risk index, detection or response action.

