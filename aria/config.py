from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


def required_env(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable is missing: {name}"
        )

    return value


@dataclass(frozen=True)
class Settings:
    ollama_url: str

    ollama_fast_model: str
    ollama_reasoning_model: str
    ollama_embedding_model: str

    ollama_timeout: int
    ollama_keep_alive: str

    splunk_url: str
    splunk_username: str
    splunk_password: str

    splunk_verify_ssl: bool
    splunk_timeout: int

    catalog_limit: int
    candidate_limit: int

    profile_event_limit: int
    profile_field_limit: int

    telemetry_db_path: str

    telemetry_retrieval_top_k: int
    telemetry_retrieval_pool: int

    telemetry_embed_batch_size: int

    field_retrieval_top_k_per_requirement: int
    field_retrieval_min_score: float
    field_retrieval_strong_score: float

    evidence_source_bundle_limit: int

    evidence_max_rounds: int


def load_settings() -> Settings:
    return Settings(
        ollama_url=required_env(
            "OLLAMA_URL"
        ).rstrip("/"),

        ollama_fast_model=required_env(
            "OLLAMA_FAST_MODEL"
        ),

        ollama_reasoning_model=required_env(
            "OLLAMA_REASONING_MODEL"
        ),

        ollama_embedding_model=required_env(
            "OLLAMA_EMBEDDING_MODEL"
        ),

        ollama_timeout=int(
            os.getenv(
                "OLLAMA_TIMEOUT",
                "600",
            )
        ),

        ollama_keep_alive=os.getenv(
            "OLLAMA_KEEP_ALIVE",
            "30m",
        ),

        splunk_url=required_env(
            "SPLUNK_URL"
        ).rstrip("/"),

        splunk_username=required_env(
            "SPLUNK_USERNAME"
        ),

        splunk_password=required_env(
            "SPLUNK_PASSWORD"
        ),

        splunk_verify_ssl=(
            os.getenv(
                "SPLUNK_VERIFY_SSL",
                "true",
            ).lower()
            == "true"
        ),

        splunk_timeout=int(
            os.getenv(
                "SPLUNK_TIMEOUT",
                "180",
            )
        ),

        catalog_limit=int(
            os.getenv(
                "CATALOG_LIMIT",
                "50",
            )
        ),

        candidate_limit=int(
            os.getenv(
                "CANDIDATE_LIMIT",
                "4",
            )
        ),

        profile_event_limit=int(
            os.getenv(
                "PROFILE_EVENT_LIMIT",
                "200",
            )
        ),

        profile_field_limit=int(
            os.getenv(
                "PROFILE_FIELD_LIMIT",
                "60",
            )
        ),

        telemetry_db_path=os.getenv(
            "TELEMETRY_DB_PATH",
            "data/telemetry_intelligence.db",
        ),

        telemetry_retrieval_top_k=int(
            os.getenv(
                "TELEMETRY_RETRIEVAL_TOP_K",
                "8",
            )
        ),

        telemetry_retrieval_pool=int(
            os.getenv(
                "TELEMETRY_RETRIEVAL_POOL",
                "50",
            )
        ),

        telemetry_embed_batch_size=int(
            os.getenv(
                "TELEMETRY_EMBED_BATCH_SIZE",
                "16",
            )
        ),

        field_retrieval_top_k_per_requirement=int(
            os.getenv(
                "FIELD_RETRIEVAL_TOP_K_PER_REQUIREMENT",
                "16",
            )
        ),

        field_retrieval_min_score=float(
            os.getenv(
                "FIELD_RETRIEVAL_MIN_SCORE",
                "0.52",
            )
        ),

        field_retrieval_strong_score=float(
            os.getenv(
                "FIELD_RETRIEVAL_STRONG_SCORE",
                "0.62",
            )
        ),

        evidence_source_bundle_limit=int(
            os.getenv(
                "EVIDENCE_SOURCE_BUNDLE_LIMIT",
                "8",
            )
        ),

        evidence_max_rounds=int(
            os.getenv(
                "EVIDENCE_MAX_ROUNDS",
                "3",
            )
        ),
    )


settings = load_settings()
