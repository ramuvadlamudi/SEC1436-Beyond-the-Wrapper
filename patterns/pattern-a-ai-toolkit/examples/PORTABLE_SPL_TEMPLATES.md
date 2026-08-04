# Portable Pattern A SPL templates

These are design templates, not searches to paste unchanged. Replace every angle-bracket placeholder with analyst-supplied or live-observed values. Keep the bound before `| ai`.

## Bounded event explanation

```spl
search index=<OBSERVED_INDEX> sourcetype=<OBSERVED_SOURCETYPE> earliest=<EARLIEST> latest=<LATEST>
| fields _time <ENTITY_FIELD> <EVENT_TEXT_FIELD>
| head <ROW_LIMIT>
| ai prompt="Explain only the supplied event. Separate observations, hypotheses and missing evidence. Event: {<EVENT_TEXT_FIELD>}" provider=Ollama model=<LOCAL_MODEL>
```

## ATT&CK candidate proposal

```spl
search index=<OBSERVED_INDEX> sourcetype=<OBSERVED_SOURCETYPE> earliest=<EARLIEST> latest=<LATEST>
| fields _time <ENTITY_FIELD> <EVENT_TEXT_FIELD>
| head <ROW_LIMIT>
| ai prompt="Propose candidate MITRE ATT&CK Enterprise technique IDs for only this event text. Return JSON with technique_id, technique_name, confidence, event_basis and uncertainty. Do not claim maliciousness. Event: {<EVENT_TEXT_FIELD>}" provider=Ollama model=<LOCAL_MODEL>
```

The result still requires validation against a pinned local ATT&CK catalogue.

## Aggregated finding summary

```spl
search index=<OBSERVED_INDEX> sourcetype=<OBSERVED_SOURCETYPE> earliest=<EARLIEST> latest=<LATEST>
| stats count min(_time) as first_seen max(_time) as last_seen by <ENTITY_FIELD> <OUTCOME_FIELD>
| sort - count
| head <ROW_LIMIT>
| ai prompt="Summarise the supplied aggregate without inferring maliciousness. State the count, entity, outcome, time bounds and evidence gaps. Entity={<ENTITY_FIELD>}; outcome={<OUTCOME_FIELD>}; count={count}; first={first_seen}; last={last_seen}." provider=Ollama model=<LOCAL_MODEL>
```

## SPL review request without execution

```spl
| makeresults
| eval proposed_spl="<ANALYST_SUPPLIED_SPL>"
| ai prompt="Review this SPL without executing it. Identify commands that may be expensive or unsafe, semantic dependencies that must be preserved, and a proposed rewrite. Do not invent indexes, fields, values or thresholds. SPL: {proposed_spl}" provider=Ollama model=<LOCAL_MODEL>
```

Any rewrite must pass a separate SPL validator and bounded equivalence test before use.

