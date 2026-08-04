from __future__ import annotations

import json
import re

from typing import (
    Any,
    Iterable,
)

import requests
import urllib3

from aria.config import settings

from aria.models import (
    CatalogItem,
    CandidateSource,
    FieldEvidence,
    SourceProfile,
)


if not settings.splunk_verify_ssl:
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )


_TIME_PATTERN = re.compile(
    r"^[A-Za-z0-9@+\-:.]+$"
)


def _safe_time(
    value: str,
    fallback: str,
) -> str:

    value = value.strip()

    if _TIME_PATTERN.fullmatch(value):
        return value

    return fallback


def _spl_quote(
    value: str,
) -> str:

    escaped = (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
    )

    return f'"{escaped}"'


def _to_int(
    value: Any,
) -> int | None:

    try:
        return int(
            float(value)
        )

    except (
        TypeError,
        ValueError,
    ):
        return None


def _flatten_values(
    value: Any,
) -> list[str]:

    if value is None:
        return []


    if isinstance(
        value,
        list,
    ):

        items: Iterable[Any] = value

    else:

        items = [value]


    output: list[str] = []


    for item in items:

        if item is None:
            continue


        if isinstance(
            item,
            (
                dict,
                list,
            ),
        ):

            text = json.dumps(
                item,
                ensure_ascii=False,
            )

        else:

            text = str(
                item
            )


        text = text.strip()


        if not text:
            continue


        output.append(
            text
        )


    return output


def _compact_summary_value(
    value: Any,
) -> str | None:

    if value is None:
        return None


    if isinstance(
        value,
        (
            dict,
            list,
        ),
    ):

        text = json.dumps(
            value,
            ensure_ascii=False,
        )

    else:

        text = str(
            value
        )


    text = text.strip()


    if not text:
        return None


    return text[:1000]


class SplunkClient:
    """
    Read-oriented Splunk REST client.

    ARIA does not hardcode source names, field names,
    event IDs, vendors or security mappings.
    """


    def __init__(self) -> None:

        self.base_url = settings.splunk_url

        self.auth = (
            settings.splunk_username,
            settings.splunk_password,
        )

        self.verify_ssl = settings.splunk_verify_ssl

        self.timeout = settings.splunk_timeout

        self.session = requests.Session()


    def search(
        self,
        spl: str,
    ) -> list[dict[str, Any]]:
        """
        Execute a Splunk search through the export endpoint.

        Do not pass search_mode here. Some Splunk versions
        reject that parameter on /services/search/v2/jobs/export.
        """

        endpoint = (
            f"{self.base_url}"
            "/services/search/v2/jobs/export"
        )


        response = self.session.post(
            endpoint,

            auth=self.auth,

            data={
                "search": spl.strip(),
                "output_mode": "json",
            },

            verify=self.verify_ssl,

            stream=True,

            timeout=self.timeout,
        )


        try:

            response.raise_for_status()

        except requests.exceptions.HTTPError as exc:

            body = response.text[:3000]

            print()
            print("[SPLUNK HTTP ERROR]")
            print(f"Status: {response.status_code}")
            print("Response body:")
            print(body)
            print()
            print("SPL that failed:")
            print(spl.strip()[:3000])
            print()

            raise exc


        results: list[
            dict[str, Any]
        ] = []


        for line in response.iter_lines(
            decode_unicode=True
        ):

            if not line:
                continue


            try:

                item = json.loads(
                    line
                )

            except json.JSONDecodeError:

                print(
                    "[SPLUNK WARNING] "
                    "Ignored non-JSON response line"
                )

                continue


            if item.get("preview") is True:
                continue


            result = item.get(
                "result"
            )


            if isinstance(
                result,
                dict,
            ):

                results.append(
                    result
                )


            messages = item.get(
                "messages"
            )


            if messages:

                for message in messages:

                    message_type = (
                        message.get(
                            "type",
                            "UNKNOWN",
                        )
                    )

                    message_text = (
                        message.get(
                            "text",
                            "",
                        )
                    )


                    print(
                        f"[SPLUNK {message_type}] "
                        f"{message_text}"
                    )


        return results


    # =================================================
    # Catalog discovery
    # =================================================


    def discover_catalog(
        self,
    ) -> list[CatalogItem]:

        limit = settings.catalog_limit


        spl = f"""
        | tstats
            count as event_count
            earliest(_time) as first_seen
            latest(_time) as last_seen
            where index=*
            by index sourcetype

        | sort - event_count

        | head {limit}
        """


        rows = self.search(
            spl
        )


        catalog: list[
            CatalogItem
        ] = []


        for row in rows:

            index = str(
                row.get(
                    "index",
                    "",
                )
            ).strip()


            sourcetype = str(
                row.get(
                    "sourcetype",
                    "",
                )
            ).strip()


            if not index or not sourcetype:
                continue


            catalog.append(
                CatalogItem(
                    index=index,

                    sourcetype=sourcetype,

                    event_count=(
                        _to_int(
                            row.get(
                                "event_count"
                            )
                        )
                        or 0
                    ),

                    first_seen=(
                        str(
                            row[
                                "first_seen"
                            ]
                        )
                        if row.get(
                            "first_seen"
                        )
                        is not None
                        else None
                    ),

                    last_seen=(
                        str(
                            row[
                                "last_seen"
                            ]
                        )
                        if row.get(
                            "last_seen"
                        )
                        is not None
                        else None
                    ),
                )
            )


        return catalog


    # =================================================
    # Source access probe
    # =================================================


    def source_event_count(
        self,
        candidate: CandidateSource,
        earliest: str,
        latest: str,
    ) -> int:

        safe_earliest = _safe_time(
            earliest,
            "0",
        )

        safe_latest = _safe_time(
            latest,
            "now",
        )


        index_value = _spl_quote(
            candidate.index
        )

        sourcetype_value = _spl_quote(
            candidate.sourcetype
        )


        spl = f"""
        search
            index={index_value}
            sourcetype={sourcetype_value}
            earliest={safe_earliest}
            latest={safe_latest}

        | stats count as source_event_count
        """


        rows = self.search(
            spl
        )


        if not rows:
            return 0


        return (
            _to_int(
                rows[0].get(
                    "source_event_count"
                )
            )
            or 0
        )


    # =================================================
    # Python row profiling
    # =================================================


    def _profile_rows(
        self,
        rows: list[
            dict[str, Any]
        ],
    ) -> list[FieldEvidence]:

        field_limit = settings.profile_field_limit

        field_stats: dict[
            str,
            dict[str, Any],
        ] = {}


        for row in rows:

            for field_name, raw_value in row.items():

                if field_name == "_raw":
                    continue


                values = _flatten_values(
                    raw_value
                )


                if not values:
                    continue


                stats = field_stats.setdefault(
                    field_name,

                    {
                        "count": 0,
                        "distinct": set(),
                        "samples": [],
                    },
                )


                stats["count"] += 1


                for value in values:

                    compact = value[:300]


                    if (
                        len(
                            stats["distinct"]
                        )
                        < 1000
                    ):

                        stats[
                            "distinct"
                        ].add(
                            compact
                        )


                    if (
                        compact
                        not in stats["samples"]
                        and len(
                            stats["samples"]
                        )
                        < 5
                    ):

                        stats[
                            "samples"
                        ].append(
                            compact
                        )


        ordered = sorted(
            field_stats.items(),

            key=lambda item: (
                -item[1]["count"],
                item[0],
            ),
        )


        output: list[
            FieldEvidence
        ] = []


        for field_name, stats in ordered[
            :field_limit
        ]:

            output.append(
                FieldEvidence(
                    name=field_name,

                    count=stats[
                        "count"
                    ],

                    distinct_count=len(
                        stats[
                            "distinct"
                        ]
                    ),

                    sample_values=json.dumps(
                        stats[
                            "samples"
                        ],
                        ensure_ascii=False,
                    ),
                )
            )


        return output


    # =================================================
    # Fieldsummary profiling
    # =================================================


    def _fieldsummary_profile(
        self,
        candidate: CandidateSource,
        earliest: str,
        latest: str,
        enrichment_mode: str,
    ) -> list[FieldEvidence]:

        safe_earliest = _safe_time(
            earliest,
            "0",
        )

        safe_latest = _safe_time(
            latest,
            "now",
        )


        event_limit = settings.profile_event_limit

        field_limit = settings.profile_field_limit


        index_value = _spl_quote(
            candidate.index
        )

        sourcetype_value = _spl_quote(
            candidate.sourcetype
        )


        enrichment_spl = ""

        if enrichment_mode == "extract":

            enrichment_spl = """
            | extract
            """

        elif enrichment_mode == "extract_spath":

            enrichment_spl = """
            | extract
            | spath
            """


        spl = f"""
        search
            index={index_value}
            sourcetype={sourcetype_value}
            earliest={safe_earliest}
            latest={safe_latest}

        | head {event_limit}

        {enrichment_spl}

        | fieldsummary maxvals=10

        | table
            field
            count
            distinct_count
            values

        | sort - count

        | head {field_limit}
        """


        try:

            rows = self.search(
                spl
            )

        except Exception as exc:

            print(
                f"  fieldsummary "
                f"{enrichment_mode} failed: {exc}"
            )

            return []


        output: list[
            FieldEvidence
        ] = []


        for row in rows:

            field_name = str(
                row.get(
                    "field",
                    "",
                )
            ).strip()


            if not field_name:
                continue


            output.append(
                FieldEvidence(
                    name=field_name,

                    count=_to_int(
                        row.get(
                            "count"
                        )
                    ),

                    distinct_count=_to_int(
                        row.get(
                            "distinct_count"
                        )
                    ),

                    sample_values=(
                        _compact_summary_value(
                            row.get(
                                "values"
                            )
                        )
                    ),
                )
            )


        return output


    def _merge_profiles(
        self,
        profile_sets: list[
            list[FieldEvidence]
        ],
    ) -> list[FieldEvidence]:

        merged: dict[
            str,
            FieldEvidence,
        ] = {}


        for fields in profile_sets:

            for field in fields:

                existing = merged.get(
                    field.name
                )


                if existing is None:

                    merged[
                        field.name
                    ] = field

                    continue


                existing_score = (
                    (existing.count or 0)
                    +
                    len(
                        existing.sample_values
                        or ""
                    )
                    +
                    (existing.distinct_count or 0)
                )


                new_score = (
                    (field.count or 0)
                    +
                    len(
                        field.sample_values
                        or ""
                    )
                    +
                    (field.distinct_count or 0)
                )


                if new_score > existing_score:

                    merged[
                        field.name
                    ] = field


        ordered = sorted(
            merged.values(),

            key=lambda field: (
                -(
                    field.count
                    if field.count is not None
                    else 0
                ),
                field.name,
            ),
        )


        return ordered[
            :settings.profile_field_limit
        ]


    # =================================================
    # Hybrid source profiler
    # =================================================


    def profile_source(
        self,
        candidate: CandidateSource,
        earliest: str,
        latest: str,
    ) -> SourceProfile:

        safe_earliest = _safe_time(
            earliest,
            "0",
        )

        safe_latest = _safe_time(
            latest,
            "now",
        )


        event_limit = settings.profile_event_limit


        index_value = _spl_quote(
            candidate.index
        )

        sourcetype_value = _spl_quote(
            candidate.sourcetype
        )


        sample_spl = f"""
        search
            index={index_value}
            sourcetype={sourcetype_value}
            earliest={safe_earliest}
            latest={safe_latest}

        | head {event_limit}
        """


        rows = self.search(
            sample_spl
        )


        print(
            f"  sample events returned: "
            f"{len(rows)}"
        )


        if not rows:

            count = self.source_event_count(
                candidate=candidate,
                earliest=earliest,
                latest=latest,
            )


            print(
                f"  source event count probe: "
                f"{count}"
            )


            return SourceProfile(
                index=candidate.index,

                sourcetype=candidate.sourcetype,

                rationale=candidate.rationale,

                fields=[],
            )


        raw_fields = self._profile_rows(
            rows
        )


        base_summary = self._fieldsummary_profile(
            candidate=candidate,
            earliest=earliest,
            latest=latest,
            enrichment_mode="base",
        )


        extract_summary = self._fieldsummary_profile(
            candidate=candidate,
            earliest=earliest,
            latest=latest,
            enrichment_mode="extract",
        )


        structured_summary = self._fieldsummary_profile(
            candidate=candidate,
            earliest=earliest,
            latest=latest,
            enrichment_mode="extract_spath",
        )


        final_fields = self._merge_profiles(
            [
                raw_fields,
                base_summary,
                extract_summary,
                structured_summary,
            ]
        )


        print(
            f"  raw fields: "
            f"{len(raw_fields)}"
        )

        print(
            f"  fieldsummary base fields: "
            f"{len(base_summary)}"
        )

        print(
            f"  fieldsummary extract fields: "
            f"{len(extract_summary)}"
        )

        print(
            f"  fieldsummary extract+spath fields: "
            f"{len(structured_summary)}"
        )

        print(
            f"  merged fields: "
            f"{len(final_fields)}"
        )


        return SourceProfile(
            index=candidate.index,

            sourcetype=candidate.sourcetype,

            rationale=candidate.rationale,

            fields=final_fields,
        )


splunk_client = SplunkClient()
