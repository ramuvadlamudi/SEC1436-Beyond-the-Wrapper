# SEC1436 implementation patterns

This repository presents three complementary ways to bring private AI into a Splunk security workflow. They are deliberately separated because they provide different levels of speed, control and engineering depth.

| Pattern | Purpose | Status in this repository | Start here |
|---|---|---|---|
| A — AI Toolkit `| ai` + local Ollama | Add bounded local-model assistance directly to an SPL pipeline | Validated demonstration pattern and operating guidance | [Pattern A](pattern-a-ai-toolkit/README.md) |
| B — ARIA lightweight agents | Route analyst goals through deterministic controls, local reasoning and live read-only Splunk evidence | Implemented product: ARIA v3.0.0-rc11 | [ARIA architecture](../docs/ARCHITECTURE.md) |
| C — DSDL + private cyber RAG | Add specialist retrieval, graph context, custom analytics and model lifecycle workflows | Experimental capabilities to try next; not implemented by RC11 | [Pattern C](pattern-c-dsdl-rag/README.md) |

The patterns are an adoption path, not three mandatory components:

1. Prove private inference quickly with Pattern A.
2. Add evidence, safety, agent contracts and approvals with Pattern B.
3. Experiment with specialised retrieval and models through Pattern C when the platform and governance prerequisites exist.

The shared design rule is:

> The LLM proposes. Splunk proves. Deterministic services enforce. Analysts approve.

Pattern A does not inherit the evidence ledger or deterministic qualification controls of Pattern B. Pattern C does not extend RC11 authority and must not be represented as a released ARIA capability.

