from __future__ import annotations

import json
import time
from typing import Any, TypeVar

import requests
from pydantic import BaseModel

from aria.config import settings


ModelType = TypeVar(
    "ModelType",
    bound=BaseModel,
)


class OllamaClient:
    """
    Local Ollama client for ARIA.

    Model roles:

    fast:
        Frequent agent operations such as:
        - intent classification
        - structured planning
        - candidate ranking
        - evidence binding decisions
        - bounded SPL compilation tasks

    reasoning:
        Expensive reasoning operations such as:
        - investigation synthesis
        - multi-source evidence analysis
        - risk reasoning
        - final analyst guidance

    Important design rule:

    The reasoning model should only receive narrowed,
    validated evidence. It should not receive the complete
    Splunk telemetry catalog.
    """

    def __init__(self) -> None:
        self.base_url = settings.ollama_url.rstrip("/")

        #
        # Backward compatibility:
        #
        # Prefer the new two-model configuration.
        # Fall back to the older single-model configuration
        # if it still exists.
        #

        old_model = getattr(
            settings,
            "ollama_model",
            None,
        )

        self.fast_model = getattr(
            settings,
            "ollama_fast_model",
            old_model,
        )

        self.reasoning_model = getattr(
            settings,
            "ollama_reasoning_model",
            self.fast_model,
        )

        if not self.fast_model:
            raise RuntimeError(
                "No Ollama fast model is configured. "
                "Set OLLAMA_FAST_MODEL in .env."
            )

        if not self.reasoning_model:
            self.reasoning_model = self.fast_model

        self.timeout = getattr(
            settings,
            "ollama_timeout",
            600,
        )

        self.keep_alive = getattr(
            settings,
            "ollama_keep_alive",
            "30m",
        )

        self.session = requests.Session()


    def _select_model(
        self,
        model_role: str,
    ) -> str:
        """
        Resolve a logical ARIA model role
        to an installed Ollama model.
        """

        if model_role == "fast":
            return self.fast_model

        if model_role == "reasoning":
            return self.reasoning_model

        raise ValueError(
            "model_role must be either "
            "'fast' or 'reasoning'"
        )


    def _post_chat(
        self,
        payload: dict[str, Any],
        model_name: str,
        purpose: str,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """
        Execute an Ollama chat request with:
        - timing diagnostics
        - timeout handling
        - response validation
        """

        request_timeout = (
            timeout
            if timeout is not None
            else self.timeout
        )

        start_time = time.monotonic()

        print(
            f"[OLLAMA] purpose={purpose} "
            f"model={model_name}"
        )

        try:
            response = self.session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=request_timeout,
            )

            response.raise_for_status()

        except requests.exceptions.ReadTimeout as exc:
            elapsed = time.monotonic() - start_time

            raise RuntimeError(
                f"Ollama timed out after "
                f"{elapsed:.1f} seconds. "
                f"model={model_name}, "
                f"purpose={purpose}. "
                "Do not solve this by sending a larger "
                "prompt or increasing the timeout indefinitely."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Cannot connect to Ollama at "
                f"{self.base_url}. "
                "Check network connectivity and "
                "the Ollama service."
            ) from exc

        except requests.exceptions.HTTPError as exc:
            response_text = (
                exc.response.text[:2000]
                if exc.response is not None
                else ""
            )

            raise RuntimeError(
                f"Ollama HTTP error for "
                f"model={model_name}: "
                f"{exc}. "
                f"Response={response_text}"
            ) from exc


        elapsed = time.monotonic() - start_time

        print(
            f"[OLLAMA] completed "
            f"purpose={purpose} "
            f"model={model_name} "
            f"elapsed={elapsed:.1f}s"
        )


        try:
            body = response.json()

        except ValueError as exc:
            raise RuntimeError(
                "Ollama returned a non-JSON response: "
                f"{response.text[:2000]}"
            ) from exc


        if "message" not in body:
            raise RuntimeError(
                "Unexpected Ollama response. "
                "Missing 'message' object. "
                f"Response={str(body)[:2000]}"
            )


        if "content" not in body["message"]:
            raise RuntimeError(
                "Unexpected Ollama response. "
                "Missing message.content. "
                f"Response={str(body)[:2000]}"
            )


        return body


    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        model_role: str = "fast",
        num_predict: int = 500,
        timeout: int | None = None,
    ) -> str:
        """
        Perform a normal text chat operation.

        Default model role is FAST.

        This is deliberate.

        The reasoning model must be requested explicitly:

            ollama_client.chat(
                ...,
                model_role="reasoning",
            )
        """

        selected_model = self._select_model(
            model_role
        )


        payload = {
            "model": selected_model,

            "stream": False,

            "keep_alive": self.keep_alive,

            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],

            "options": {
                "temperature": temperature,

                #
                # Bound output generation.
                #
                # ARIA nodes should be concise and
                # task-specific rather than generating
                # unlimited prose.
                #

                "num_predict": num_predict,
            },
        }


        body = self._post_chat(
            payload=payload,
            model_name=selected_model,
            purpose=f"text-{model_role}",
            timeout=timeout,
        )


        return (
            body["message"]["content"]
            .strip()
        )


    def structured_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ModelType],
        model_role: str = "fast",
        num_predict: int = 700,
        timeout: int | None = None,
    ) -> ModelType:
        """
        Request schema-constrained structured output
        from Ollama.

        Used for:
        - TaskPlan
        - candidate ranking
        - evidence binding
        - semantic validation decisions
        - other machine-readable agent decisions

        Default model role is FAST.
        """

        selected_model = self._select_model(
            model_role
        )


        schema: dict[str, Any] = (
            response_model.model_json_schema()
        )


        payload = {
            "model": selected_model,

            "stream": False,

            "keep_alive": self.keep_alive,

            #
            # Ollama accepts a JSON schema object
            # as the structured output format.
            #

            "format": schema,

            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],

            "options": {
                "temperature": 0,
                "num_predict": num_predict,
            },
        }


        body = self._post_chat(
            payload=payload,
            model_name=selected_model,
            purpose=f"structured-{model_role}",
            timeout=timeout,
        )


        raw_content = (
            body["message"]["content"]
            .strip()
        )


        try:
            parsed = json.loads(
                raw_content
            )

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Ollama structured response was not "
                "valid JSON. "
                f"Model={selected_model}. "
                f"Response={raw_content[:2000]}"
            ) from exc


        try:
            validated = (
                response_model.model_validate(
                    parsed
                )
            )

        except Exception as exc:
            raise RuntimeError(
                "Ollama JSON did not satisfy "
                "the required response schema. "
                f"Model={selected_model}. "
                f"Response={raw_content[:2000]}"
            ) from exc


        return validated


    def embed_texts(
        self,
        texts: list[str],
        timeout: int | None = None,
    ) -> list[list[float]]:
        """Create local embeddings for a bounded list of texts.

        ARIA uses embeddings only for generic semantic retrieval and observed
        schema matching. The method supports both the current Ollama batch
        endpoint and the legacy single-prompt endpoint so customer deployments
        are not coupled to one Ollama minor version.
        """
        cleaned = [str(item or "").strip() for item in texts]
        if not cleaned:
            return []

        model_name = settings.ollama_embedding_model
        request_timeout = timeout if timeout is not None else min(self.timeout, 60)
        started = time.monotonic()
        payload = {
            "model": model_name,
            "input": cleaned,
            "truncate": True,
            "keep_alive": self.keep_alive,
        }

        try:
            response = self.session.post(
                f"{self.base_url}/api/embed",
                json=payload,
                timeout=request_timeout,
            )
            if response.status_code == 404:
                raise FileNotFoundError("Ollama batch embedding endpoint unavailable")
            response.raise_for_status()
            body = response.json()
            embeddings = body.get("embeddings")
            if not isinstance(embeddings, list):
                raise RuntimeError(
                    "Ollama embedding response did not contain an embeddings list."
                )
            vectors = [
                [float(value) for value in vector]
                for vector in embeddings
                if isinstance(vector, list)
            ]
            if len(vectors) != len(cleaned):
                raise RuntimeError(
                    "Ollama embedding response count did not match the input count."
                )
            print(
                f"[OLLAMA] completed purpose=embedding-batch "
                f"model={model_name} inputs={len(cleaned)} "
                f"elapsed={time.monotonic() - started:.1f}s"
            )
            return vectors
        except FileNotFoundError:
            pass
        except requests.exceptions.ReadTimeout as exc:
            raise RuntimeError(
                f"Ollama embedding timed out after "
                f"{time.monotonic() - started:.1f} seconds. model={model_name}."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Ollama embedding request failed for model={model_name}: {exc}"
            ) from exc
        except ValueError as exc:
            raise RuntimeError(
                "Ollama embedding endpoint returned invalid JSON."
            ) from exc

        # Compatibility fallback for older Ollama versions.
        output: list[list[float]] = []
        for item in cleaned:
            legacy = self.session.post(
                f"{self.base_url}/api/embeddings",
                json={
                    "model": model_name,
                    "prompt": item,
                    "keep_alive": self.keep_alive,
                },
                timeout=request_timeout,
            )
            legacy.raise_for_status()
            body = legacy.json()
            vector = body.get("embedding")
            if not isinstance(vector, list):
                raise RuntimeError(
                    "Legacy Ollama embedding response did not contain an embedding list."
                )
            output.append([float(value) for value in vector])
        print(
            f"[OLLAMA] completed purpose=embedding-legacy "
            f"model={model_name} inputs={len(cleaned)} "
            f"elapsed={time.monotonic() - started:.1f}s"
        )
        return output


    def health(self) -> dict[str, Any]:
        """
        Check Ollama connectivity and return
        the installed model inventory.
        """

        try:
            response = self.session.get(
                f"{self.base_url}/api/tags",
                timeout=15,
            )

            response.raise_for_status()

            return response.json()

        except requests.RequestException as exc:
            raise RuntimeError(
                f"Ollama health check failed: {exc}"
            ) from exc


    def preload(
        self,
        model_role: str = "fast",
    ) -> None:
        """
        Load a configured model into Ollama memory.

        Useful before a demo or test sequence.
        """

        selected_model = self._select_model(
            model_role
        )


        payload = {
            "model": selected_model,

            "stream": False,

            "keep_alive": self.keep_alive,

            "messages": [],
        }


        print(
            f"[OLLAMA] preloading "
            f"model={selected_model}"
        )


        try:
            response = self.session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )

            response.raise_for_status()

        except requests.RequestException as exc:
            raise RuntimeError(
                f"Failed to preload "
                f"{selected_model}: {exc}"
            ) from exc


        print(
            f"[OLLAMA] model ready: "
            f"{selected_model}"
        )


ollama_client = OllamaClient()
