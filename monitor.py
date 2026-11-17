import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests


# ============================================================
# GLOBAL INFRASTRUCTURE MONITOR
# CORRELATION GROUPING DRY RUN
#
# THIS VERSION:
#
#   - Loads organizations.json
#   - Runs synthetic organization/correlation tests
#   - Retrieves live Cloudflare Radar events
#   - Identifies watched organizations and sectors
#   - Groups distinct organizations by time and sector
#   - Detects same-sector and cross-sector correlations
#   - Calculates correlation severity
#   - Calculates confidence separately from severity
#
# THIS VERSION DOES NOT:
#
#   - Send email
#   - Read or modify production state.json
#   - Modify correlation-state.json
#   - Change the production workflow
# ============================================================


CLOUDFLARE_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/annotations/outages"
)

ORGANIZATION_FILE = Path("organizations.json")

SAME_SECTOR_WINDOW_MINUTES = 60
CROSS_SECTOR_WINDOW_MINUTES = 45

HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80

MINIMUM_EMAIL_CONFIDENCE = 50


# ============================================================
# DATE AND TIME HELPERS
# ============================================================

def parse_datetime(value):

    if not value:
        return None

    if isinstance(value, datetime):
        return value

    try:
        parsed = datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00",
            )
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except ValueError:
        return None


def format_datetime(value):

    parsed = parse_datetime(value)

    if parsed is None:
        return "Unknown"

    return parsed.isoformat()


def minutes_between(
    first_value,
    second_value,
):

    first = parse_datetime(
        first_value
    )

    second = parse_datetime(
        second_value
    )

    if not first or not second:
        return None

    difference = abs(
        second - first
    )

    return (
        difference.total_seconds()
        / 60
    )


# ============================================================
# LOAD ORGANIZATION CATALOG
# ============================================================

def load_organizations():

    if not ORGANIZATION_FILE.exists():

        print()
        print("ERROR:")
        print(
            "organizations.json was not found."
        )

        sys.exit(1)

    try:

        with ORGANIZATION_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

    except json.JSONDecodeError as error:

        print()
        print("ERROR:")
        print(
            "organizations.json contains invalid JSON."
        )
        print(error)

        sys.exit(1)

    organizations = data.get(
        "organizations",
        {},
    )

    if not organizations:

        print()
        print("ERROR:")
        print(
            "No organizations were found "
            "in organizations.json."
        )

        sys.exit(1)

    print(
        f"Loaded {len(organizations)} "
        f"organizations."
    )

    return organizations


# ============================================================
# ALIAS MATCHING
# ============================================================

def alias_matches(
    text,
    alias,
):

    alias = str(alias).strip()

    if not alias:
        return False

    pattern = (
        r"(?<!\w)"
        + re.escape(alias)
        + r"(?!\w)"
    )

    return bool(
        re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        )
    )


def create_searchable_text(event):

    fields = [
        event.get("description", ""),
        event.get("scope", ""),
        event.get("locations", ""),
        event.get("asns", ""),
        event.get("event_type", ""),
        event.get("outage_type", ""),
        event.get("cause", ""),
        event.get("infrastructure_text", ""),
    ]

    return " ".join(
        str(field)
        for field in fields
        if field
    ).lower()


def identify_organizations(
    event,
    organizations,
):

    searchable_text = (
        create_searchable_text(
            event
        )
    )

    matches = []

    for (
        organization_id,
        organization
    ) in organizations.items():

        aliases = organization.get(
            "aliases",
            [],
        )

        matched_aliases = []

        for alias in aliases:

            if alias_matches(
                searchable_text,
                alias,
            ):

                matched_aliases.append(
                    alias
                )

        if matched_aliases:

            matches.append({

                "id":
                    organization_id,

                "display_name":
                    organization.get(
                        "display_name",
                        organization_id,
                    ),

                "sector":
                    organization.get(
                        "sector",
                        "unknown",
                    ),

                "criticality":
                    int(
                        organization.get(
                            "criticality",
                            0,
                        )
                    ),

                "matched_aliases":
                    matched_aliases,
            })

    return matches


# ============================================================
# NORMALIZED EVENT CREATION
# ============================================================

def create_normalized_event(
    event_id,
    source,
    description,
    started,
    locations="Unknown",
    asns="Unknown",
    scope="Unknown",
    event_type="OUTAGE",
    outage_type="Unknown",
    cause="Unknown",
    status="ONGOING",
    source_url="",
    official_acknowledgment=False,
    infrastructure=None,
):

    if infrastructure is None:
        infrastructure = []

    return {
        "event_id":
            event_id,

        "source":
            source,

        "description":
            description,

        "started":
            format_datetime(
                started
            ),

        "ended":
            None,

        "locations":
            locations,

        "asns":
            asns,

        "scope":
            scope,

        "event_type":
            event_type,

        "outage_type":
            outage_type,

        "cause":
            cause,

        "status":
            status,

        "source_url":
            source_url,

        "official_acknowledgment":
            official_acknowledgment,

        "infrastructure":
            infrastructure,

        "infrastructure_text":
            " ".join(
                infrastructure
            ),

        "organizations":
            [],

        "organization_ids":
            [],

        "organization_names":
            [],

        "sectors":
            [],
    }


def enrich_event_with_organizations(
    event,
    organizations,
):

    matches = identify_organizations(
        event,
        organizations,
    )

    event["organizations"] = matches

    event["organization_ids"] = sorted({
        organization["id"]
        for organization in matches
    })

    event["organization_names"] = sorted({
        organization["display_name"]
        for organization in matches
    })

    event["sectors"] = sorted({
        organization["sector"]
        for organization in matches
    })

    return event


# ============================================================
# CLOUDFLARE RADAR
# ============================================================

def get_cloudflare_outages():

    print()
    print(
        "Connecting to Cloudflare Radar..."
    )

    token = os.environ.get(
        "CLOUDFLARE_API_TOKEN",
        "",
    ).strip()

    if not token:

        print()
        print("ERROR:")
        print(
            "CLOUDFLARE_API_TOKEN was not found."
        )

        sys.exit(1)

    headers = {
        "Authorization":
            f"Bearer {token}",

        "Accept":
            "application/json",

        "User-Agent":
            "global-infrastructure-monitor/3.0",
    }

    params = {
        "dateRange": "1d",
        "limit": 50,
        "format": "json",
    }

    try:

        response = requests.get(
            CLOUDFLARE_URL,
            headers=headers,
            params=params,
            timeout=30,
        )

        print(
            "Cloudflare HTTP status:",
            response.status_code,
        )

        response.raise_for_status()

    except requests.exceptions.RequestException as error:

        print()
        print(
            "ERROR connecting to Cloudflare Radar:"
        )
        print(error)

        sys.exit(1)

    try:

        data = response.json()

    except ValueError:

        print()
        print(
            "ERROR: Cloudflare returned invalid JSON."
        )

        sys.exit(1)

    if data.get("success") is False:

        print()
        print(
            "Cloudflare API reported an error:"
        )
        print(
            data.get("errors")
        )

        sys.exit(1)

    return (
        data.get("result", {})
        .get("annotations", [])
    )


def normalize_cloudflare_event(
    raw_event,
    sequence_number,
):

    outage = (
        raw_event.get("outage")
        or {}
    )

    locations = (
        raw_event.get("locations")
        or []
    )

    asns = (
        raw_event.get("asns")
        or []
    )

    if isinstance(locations, list):

        location_text = ", ".join(
            str(value)
            for value in locations
        )

    else:

        location_text = str(
            locations
        )

    if isinstance(asns, list):

        asn_text = ", ".join(
            str(value)
            for value in asns
        )

    else:

        asn_text = str(
            asns
        )

    ended = raw_event.get(
        "endDate"
    )

    event = create_normalized_event(
        event_id=(
            f"cloudflare-{sequence_number}"
        ),
        source="cloudflare_radar",
        description=(
            raw_event.get("description")
            or "No description provided"
        ),
        started=(
            raw_event.get("startDate")
        ),
        locations=(
            location_text
            or "Unknown"
        ),
        asns=(
            asn_text
            or "Unknown"
        ),
        scope=(
            raw_event.get("scope")
            or "Unknown"
        ),
        event_type=(
            raw_event.get("eventType")
            or "OUTAGE"
        ),
        outage_type=(
            outage.get("outageType")
            or "Unknown"
        ),
        cause=(
            outage.get("outageCause")
            or "Unknown"
        ),
        status=(
            "RESOLVED"
            if ended
            else "ONGOING"
        ),
        source_url=(
            raw_event.get("linkedUrl")
            or ""
        ),
        official_acknowledgment=False,
        infrastructure=[],
    )

    event["ended"] = ended

    return event


# ============================================================
# CORRELATION ELIGIBILITY
# ============================================================

def distinct_organization_ids(events):

    return sorted({
        organization_id
        for event in events
        for organization_id
        in event["organization_ids"]
    })


def distinct_organization_names(events):

    return sorted({
        organization_name
        for event in events
        for organization_name
        in event["organization_names"]
    })


def distinct_sectors(events):

    return sorted({
        sector
        for event in events
        for sector in event["sectors"]
    })


def distinct_sources(events):

    return sorted({
        event["source"]
        for event in events
    })


def shared_infrastructure(events):

    if not events:
        return []

    infrastructure_sets = []

    for event in events:

        values = {
            value.lower()
            for value
            in event.get(
                "infrastructure",
                [],
            )
        }

        if values:
            infrastructure_sets.append(
                values
            )

    if len(infrastructure_sets) < 2:
        return []

    counts = Counter()

    for values in infrastructure_sets:

        for value in values:
            counts[value] += 1

    return sorted(
        value
        for value, count
        in counts.items()
        if count >= 2
    )


def event_time_span_minutes(events):

    timestamps = [
        parse_datetime(
            event["started"]
        )
        for event in events
    ]

    timestamps = [
        timestamp
        for timestamp in timestamps
        if timestamp is not None
    ]

    if len(timestamps) < 2:
        return 0

    return (
        max(timestamps)
        - min(timestamps)
    ).total_seconds() / 60


# ============================================================
# CORRELATION GROUP BUILDING
# ============================================================

def build_same_sector_groups(events):

    groups = []

    sectors = sorted({
        sector
        for event in events
        for sector in event["sectors"]
    })

    for sector in sectors:

        sector_events = [
            event
            for event in events
            if sector in event["sectors"]
        ]

        sector_events.sort(
            key=lambda event:
                parse_datetime(
                    event["started"]
                )
                or datetime.min.replace(
                    tzinfo=timezone.utc
                )
        )

        for starting_index in range(
            len(sector_events)
        ):

            anchor_event = (
                sector_events[
                    starting_index
                ]
            )

            candidate_events = []

            for candidate_event in (
                sector_events[
                    starting_index:
                ]
            ):

                difference = minutes_between(
                    anchor_event["started"],
                    candidate_event["started"],
                )

                if (
                    difference is not None
                    and difference
                    <= SAME_SECTOR_WINDOW_MINUTES
                ):

                    candidate_events.append(
                        candidate_event
                    )

            organization_ids = (
                distinct_organization_ids(
                    candidate_events
                )
            )

            if len(organization_ids) >= 2:

                event_ids = sorted({
                    event["event_id"]
                    for event
                    in candidate_events
                })

                signature = (
                    sector,
                    tuple(event_ids),
                )

                if not any(
                    group["signature"]
                    == signature
                    for group in groups
                ):

                    groups.append({
                        "correlation_type":
                            "SAME_SECTOR",

                        "sector":
                            sector,

                        "events":
                            candidate_events,

                        "signature":
                            signature,
                    })

    return groups


def build_cross_sector_groups(events):

    groups = []

    sorted_events = sorted(
        events,
        key=lambda event:
            parse_datetime(
                event["started"]
            )
            or datetime.min.replace(
                tzinfo=timezone.utc
            ),
    )

    for starting_index in range(
        len(sorted_events)
    ):

        anchor_event = (
            sorted_events[
                starting_index
            ]
        )

        candidate_events = []

        for candidate_event in (
            sorted_events[
                starting_index:
            ]
        ):

            difference = minutes_between(
                anchor_event["started"],
                candidate_event["started"],
            )

            if (
                difference is not None
                and difference
                <= CROSS_SECTOR_WINDOW_MINUTES
            ):

                candidate_events.append(
                    candidate_event
                )

        organization_ids = (
            distinct_organization_ids(
                candidate_events
            )
        )

        sectors = distinct_sectors(
            candidate_events
        )

        if (
            len(organization_ids) >= 3
            and len(sectors) >= 2
        ):

            event_ids = sorted({
                event["event_id"]
                for event
                in candidate_events
            })

            signature = tuple(
                event_ids
            )

            if not any(
                group["signature"]
                == signature
                for group in groups
            ):

                groups.append({
                    "correlation_type":
                        "CROSS_SECTOR",

                    "sector":
                        None,

                    "events":
                        candidate_events,

                    "signature":
                        signature,
                })

    return groups


def remove_redundant_groups(groups):

    unique_groups = []

    for group in groups:

        group_event_ids = {
            event["event_id"]
            for event
            in group["events"]
        }

        is_redundant = False

        for existing_group in list(
            unique_groups
        ):

            if (
                group["correlation_type"]
                != existing_group[
                    "correlation_type"
                ]
            ):
                continue

            existing_event_ids = {
                event["event_id"]
                for event
                in existing_group["events"]
            }

            if (
                group_event_ids
                <= existing_event_ids
            ):

                is_redundant = True
                break

            if (
                existing_event_ids
                < group_event_ids
            ):

                unique_groups.remove(
                    existing_group
                )

        if not is_redundant:

            unique_groups.append(
                group
            )

    return unique_groups


def build_correlation_groups(events):

    useful_events = [
        event
        for event in events
        if event["organization_ids"]
    ]

    same_sector_groups = (
        build_same_sector_groups(
            useful_events
        )
    )

    cross_sector_groups = (
        build_cross_sector_groups(
            useful_events
        )
    )

    return remove_redundant_groups(
        same_sector_groups
        + cross_sector_groups
    )


# ============================================================
# CORRELATION SCORING
# ============================================================

def calculate_correlation_score(group):

    events = group["events"]

    organization_ids = (
        distinct_organization_ids(
            events
        )
    )

    sectors = distinct_sectors(
        events
    )

    sources = distinct_sources(
        events
    )

    infrastructure = (
        shared_infrastructure(
            events
        )
    )

    score = 0
    reasons = []

    organization_count = len(
        organization_ids
    )

    sector_count = len(
        sectors
    )

    source_count = len(
        sources
    )


    # Organization count

    if organization_count >= 10:

        score += 60

        reasons.append(
            "10 or more organizations +60"
        )

    elif organization_count >= 5:

        score += 45

        reasons.append(
            "5-9 organizations +45"
        )

    elif organization_count >= 3:

        score += 30

        reasons.append(
            "3-4 organizations +30"
        )

    elif organization_count == 2:

        score += 15

        reasons.append(
            "2 organizations +15"
        )


    # Same-sector concentration

    sector_counts = Counter()

    for event in events:

        for organization in event[
            "organizations"
        ]:

            sector_counts[
                organization["sector"]
            ] += 1

    highest_sector_count = (
        max(
            sector_counts.values(),
            default=0,
        )
    )

    if highest_sector_count >= 3:

        score += 20

        reasons.append(
            "3+ organizations in one sector +20"
        )

    elif highest_sector_count == 2:

        score += 10

        reasons.append(
            "2 organizations in one sector +10"
        )


    # Sector spread

    if sector_count >= 4:

        score += 35

        reasons.append(
            "4 or more sectors +35"
        )

    elif sector_count == 3:

        score += 25

        reasons.append(
            "3 sectors +25"
        )

    elif sector_count == 2:

        score += 15

        reasons.append(
            "2 sectors +15"
        )


    # Shared infrastructure

    if infrastructure:

        score += 20

        reasons.append(
            "Shared infrastructure +20"
        )


    # National/global scope

    combined_text = " ".join(
        create_searchable_text(
            event
        )
        for event in events
    )

    if any(
        term in combined_text
        for term in [
            "global",
            "nationwide",
            "national",
            "multiple countries",
        ]
    ):

        score += 15

        reasons.append(
            "National/global scope +15"
        )


    # Independent-source corroboration

    if source_count >= 3:

        score += 20

        reasons.append(
            "3+ independent sources +20"
        )

    elif source_count == 2:

        score += 10

        reasons.append(
            "2 independent sources +10"
        )


    # Single-source evidence penalty

    if source_count == 1:

        score -= 15

        reasons.append(
            "Single-source evidence -15"
        )


    return (
        max(
            0,
            min(score, 100),
        ),
        reasons,
    )


# ============================================================
# CONFIDENCE SCORING
# ============================================================

def calculate_confidence(group):

    events = group["events"]

    sources = distinct_sources(
        events
    )

    infrastructure = (
        shared_infrastructure(
            events
        )
    )

    score = 0
    reasons = []

    source_count = len(
        sources
    )

    if source_count >= 1:

        score += 30

        reasons.append(
            "At least one structured source +30"
        )

    if source_count >= 2:

        score += 30

        reasons.append(
            "Second independent source +30"
        )

    if source_count >= 3:

        score += 20

        reasons.append(
            "Third independent source +20"
        )

    if any(
        event.get(
            "official_acknowledgment",
            False,
        )
        for event in events
    ):

        score += 20

        reasons.append(
            "Official acknowledgment +20"
        )

    if infrastructure:

        score += 15

        reasons.append(
            "Shared infrastructure identified +15"
        )

    event_span = event_time_span_minutes(
        events
    )

    allowed_window = (
        SAME_SECTOR_WINDOW_MINUTES
        if group["correlation_type"]
        == "SAME_SECTOR"
        else CROSS_SECTOR_WINDOW_MINUTES
    )

    if event_span <= allowed_window:

        score += 10

        reasons.append(
            "Matching time window +10"
        )

    return (
        min(score, 100),
        reasons,
    )


def determine_severity(score):

    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"

    if score >= HIGH_THRESHOLD:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def determine_confidence(score):

    if score >= 90:
        return "CONFIRMED"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MODERATE"

    return "LOW"


def would_send_correlation_email(
    correlation_score,
    confidence_score,
):

    return (
        correlation_score
        >= HIGH_THRESHOLD
        and confidence_score
        >= MINIMUM_EMAIL_CONFIDENCE
    )


# ============================================================
# DISPLAY CORRELATION
# ============================================================

def display_correlation(
    number,
    group,
):

    events = group["events"]

    organization_names = (
        distinct_organization_names(
            events
        )
    )

    sectors = distinct_sectors(
        events
    )

    sources = distinct_sources(
        events
    )

    infrastructure = (
        shared_infrastructure(
            events
        )
    )

    correlation_score, score_reasons = (
        calculate_correlation_score(
            group
        )
    )

    confidence_score, confidence_reasons = (
        calculate_confidence(
            group
        )
    )

    severity = determine_severity(
        correlation_score
    )

    confidence = determine_confidence(
        confidence_score
    )

    email_would_send = (
        would_send_correlation_email(
            correlation_score,
            confidence_score,
        )
    )

    print()
    print("=" * 75)

    print(
        f"Correlation #{number}"
    )

    print("=" * 75)

    print(
        "Type:              "
        f"{group['correlation_type']}"
    )

    print(
        "Severity:          "
        f"{severity}"
    )

    print(
        "Correlation score: "
        f"{correlation_score}/100"
    )

    print(
        "Confidence:        "
        f"{confidence}"
    )

    print(
        "Confidence score:  "
        f"{confidence_score}/100"
    )

    print(
        "Time span:         "
        f"{event_time_span_minutes(events):.1f} minutes"
    )

    print(
        "Organizations:     "
        f"{len(organization_names)}"
    )

    for name in organization_names:

        print(
            f"  - {name}"
        )

    print(
        "Sectors:           "
        f"{len(sectors)}"
    )

    for sector in sectors:

        print(
            f"  - {sector}"
        )

    print(
        "Sources:           "
        f"{len(sources)}"
    )

    for source in sources:

        print(
            f"  - {source}"
        )

    print("Shared infrastructure:")

    if infrastructure:

        for dependency in infrastructure:

            print(
                f"  - {dependency}"
            )

    else:

        print(
            "  None identified"
        )

    print()
    print("Correlation scoring:")

    for reason in score_reasons:

        print(
            f"  + {reason}"
        )

    print()
    print("Confidence scoring:")

    for reason in confidence_reasons:

        print(
            f"  + {reason}"
        )

    print()

    if email_would_send:

        print(
            ">>> WOULD SEND CORRELATION EMAIL <<<"
        )

    else:

        print(
            "No correlation email would be sent."
        )


# ============================================================
# SYNTHETIC TEST EVENTS
# ============================================================

def build_synthetic_test_events(
    organizations,
):

    events = []


    # --------------------------------------------------------
    # TEST GROUP 1:
    # Three financial organizations within 31 minutes.
    # This should create a SAME_SECTOR group.
    # --------------------------------------------------------

    events.append(
        create_normalized_event(
            event_id="test-financial-1",
            source="test_source_a",
            description=(
                "JPMorgan Chase online banking "
                "is experiencing service problems."
            ),
            started="2026-11-17T18:00:00Z",
            official_acknowledgment=True,
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-financial-2",
            source="test_source_b",
            description=(
                "Bank of America customers "
                "are reporting online banking failures."
            ),
            started="2026-11-17T18:18:00Z",
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-financial-3",
            source="test_source_c",
            description=(
                "Wells Fargo digital banking "
                "services are unavailable."
            ),
            started="2026-11-17T18:31:00Z",
        )
    )


    # --------------------------------------------------------
    # TEST GROUP 2:
    # Three sectors within 36 minutes.
    # This should create a CROSS_SECTOR group.
    # --------------------------------------------------------

    events.append(
        create_normalized_event(
            event_id="test-cross-1",
            source="test_source_microsoft",
            description=(
                "Microsoft 365 and Outlook "
                "are experiencing a global outage."
            ),
            started="2026-11-17T20:00:00Z",
            scope="Global",
            official_acknowledgment=True,
            infrastructure=[
                "akamai"
            ],
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-cross-2",
            source="test_source_payments",
            description=(
                "Mastercard payment processing "
                "is experiencing widespread failures."
            ),
            started="2026-11-17T20:17:00Z",
            infrastructure=[
                "akamai"
            ],
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-cross-3",
            source="test_source_government",
            description=(
                "Federal Aviation Administration "
                "online services are unavailable."
            ),
            started="2026-11-17T20:36:00Z",
            infrastructure=[
                "akamai"
            ],
        )
    )


    # --------------------------------------------------------
    # TEST GROUP 3:
    # Same organization reported by three sources.
    # This must remain ONE distinct organization.
    # It must not create a correlation.
    # --------------------------------------------------------

    events.append(
        create_normalized_event(
            event_id="test-duplicate-org-1",
            source="test_source_one",
            description=(
                "Apple iCloud services "
                "are unavailable."
            ),
            started="2026-11-17T22:00:00Z",
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-duplicate-org-2",
            source="test_source_two",
            description=(
                "Apple App Store users "
                "are experiencing errors."
            ),
            started="2026-11-17T22:10:00Z",
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-duplicate-org-3",
            source="test_source_three",
            description=(
                "Apple iCloud outage continues."
            ),
            started="2026-11-17T22:20:00Z",
        )
    )


    # --------------------------------------------------------
    # TEST GROUP 4:
    # Apple and Mastercard are three hours apart.
    # They must not create a correlation.
    # --------------------------------------------------------

    events.append(
        create_normalized_event(
            event_id="test-time-1",
            source="test_time_source_a",
            description=(
                "Apple iCloud is unavailable."
            ),
            started="2026-11-18T01:00:00Z",
        )
    )

    events.append(
        create_normalized_event(
            event_id="test-time-2",
            source="test_time_source_b",
            description=(
                "Mastercard payment processing "
                "is unavailable."
            ),
            started="2026-11-18T04:00:00Z",
        )
    )


    # Enrich every event.

    return [
        enrich_event_with_organizations(
            event,
            organizations,
        )
        for event in events
    ]


# ============================================================
# AUTOMATED SYNTHETIC VALIDATION
# ============================================================

def run_synthetic_validation(
    organizations,
):

    print()
    print("=" * 75)
    print(
        " SYNTHETIC CORRELATION VALIDATION"
    )
    print("=" * 75)

    events = build_synthetic_test_events(
        organizations
    )

    groups = build_correlation_groups(
        events
    )

    financial_groups = [
        group
        for group in groups
        if (
            group["correlation_type"]
            == "SAME_SECTOR"
            and group.get("sector")
            == "financial"
        )
    ]

    cross_sector_groups = [
        group
        for group in groups
        if group["correlation_type"]
        == "CROSS_SECTOR"
    ]

    apple_only_groups = [
        group
        for group in groups
        if (
            distinct_organization_ids(
                group["events"]
            )
            == ["apple"]
        )
    ]

    long_window_group_found = False

    for group in groups:

        group_ids = (
            distinct_organization_ids(
                group["events"]
            )
        )

        if (
            "apple" in group_ids
            and "mastercard" in group_ids
            and event_time_span_minutes(
                group["events"]
            ) > 60
        ):

            long_window_group_found = True


    tests = [

        (
            "Three financial organizations "
            "create a same-sector group",
            len(financial_groups) >= 1,
        ),

        (
            "Microsoft, Mastercard and FAA "
            "create a cross-sector group",
            len(cross_sector_groups) >= 1,
        ),

        (
            "Three Apple reports remain "
            "one organization and do not correlate",
            len(apple_only_groups) == 0,
        ),

        (
            "Events three hours apart "
            "do not correlate",
            not long_window_group_found,
        ),
    ]

    all_passed = True

    for number, (
        description,
        passed,
    ) in enumerate(
        tests,
        start=1,
    ):

        if not passed:
            all_passed = False

        print()

        print(
            f"Test #{number}: "
            f"{'PASS' if passed else 'FAIL'}"
        )

        print(
            f"  {description}"
        )

    print()

    print(
        f"Synthetic events: "
        f"{len(events)}"
    )

    print(
        f"Correlation groups: "
        f"{len(groups)}"
    )

    for number, group in enumerate(
        groups,
        start=1,
    ):

        display_correlation(
            number,
            group,
        )

    print()

    if all_passed:

        print(
            "All synthetic correlation "
            "tests PASSED."
        )

    else:

        print(
            "One or more synthetic "
            "correlation tests FAILED."
        )

    return all_passed


# ============================================================
# DISPLAY LIVE EVENT
# ============================================================

def display_live_event(
    number,
    event,
):

    print()
    print("-" * 75)

    print(
        f"Live event #{number}"
    )

    print("-" * 75)

    print(
        f"Started:      "
        f"{event['started']}"
    )

    print(
        f"Status:       "
        f"{event['status']}"
    )

    print(
        f"Location:     "
        f"{event['locations']}"
    )

    print(
        f"Description:  "
        f"{event['description']}"
    )

    print(
        "Organizations:"
    )

    if event["organization_names"]:

        for name in (
            event["organization_names"]
        ):

            print(
                f"  - {name}"
            )

    else:

        print(
            "  None detected"
        )

    print(
        "Sectors:"
    )

    if event["sectors"]:

        for sector in event["sectors"]:

            print(
                f"  - {sector}"
            )

    else:

        print(
            "  None detected"
        )


# ============================================================
# PROCESS LIVE DATA
# ============================================================

def process_live_events(
    organizations,
):

    raw_outages = (
        get_cloudflare_outages()
    )

    print()

    print(
        f"Cloudflare returned "
        f"{len(raw_outages)} event(s)."
    )

    live_events = []

    for number, raw_event in enumerate(
        raw_outages,
        start=1,
    ):

        event = (
            normalize_cloudflare_event(
                raw_event,
                number,
            )
        )

        event = (
            enrich_event_with_organizations(
                event,
                organizations,
            )
        )

        live_events.append(
            event
        )

        display_live_event(
            number,
            event,
        )

    groups = build_correlation_groups(
        live_events
    )

    print()
    print("=" * 75)
    print(
        " LIVE CORRELATION RESULTS"
    )
    print("=" * 75)

    print()

    print(
        f"Live events:              "
        f"{len(live_events)}"
    )

    print(
        f"Events with organizations:"
        f" {sum(1 for event in live_events if event['organization_ids'])}"
    )

    print(
        f"Correlation groups:       "
        f"{len(groups)}"
    )

    if not groups:

        print()
        print(
            "No live multi-organization "
            "correlations were detected."
        )

        print()
        print(
            "This is normal when Cloudflare "
            "reports only one organization "
            "or unrelated events."
        )

    else:

        for number, group in enumerate(
            groups,
            start=1,
        ):

            display_correlation(
                number,
                group,
            )

    return live_events, groups


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 75)
    print(
        " GLOBAL INFRASTRUCTURE MONITOR"
    )
    print(
        " CORRELATION GROUPING DRY RUN"
    )
    print("=" * 75)

    print()
    print(
        "EMAIL DELIVERY: DISABLED"
    )
    print(
        "PRODUCTION STATE CHANGES: DISABLED"
    )
    print(
        "CORRELATION STATE CHANGES: DISABLED"
    )

    organizations = (
        load_organizations()
    )

    tests_passed = (
        run_synthetic_validation(
            organizations
        )
    )

    if not tests_passed:

        print()
        print(
            "Stopping because one or more "
            "synthetic tests failed."
        )

        sys.exit(1)

    live_events, live_groups = (
        process_live_events(
            organizations
        )
    )

    print()
    print()
    print("=" * 75)
    print(
        " CORRELATION DRY RUN SUMMARY"
    )
    print("=" * 75)

    print()

    print(
        "Synthetic correlation tests: PASSED"
    )

    print(
        f"Live Cloudflare events:   "
        f"{len(live_events)}"
    )

    print(
        f"Live correlation groups:  "
        f"{len(live_groups)}"
    )

    print()

    print(
        "EMAIL DELIVERY REMAINS DISABLED."
    )

    print(
        "No production or correlation "
        "state files were modified."
    )

    print()

    print(
        "Correlation grouping dry run "
        "completed successfully."
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()
