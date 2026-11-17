import json
import os
import re
import sys
from pathlib import Path

import requests


# ============================================================
# GLOBAL INFRASTRUCTURE MONITOR
# ORGANIZATION MATCHING - DRY RUN
#
# THIS VERSION:
#
#   - Reads organizations.json
#   - Queries Cloudflare Radar
#   - Examines outage descriptions/details
#   - Identifies organizations by aliases
#   - Identifies affected sectors
#   - Displays organization criticality
#
# THIS VERSION DOES NOT:
#
#   - Send email
#   - Modify production state.json
#   - Create correlations
#   - Affect the production monitor
# ============================================================


CLOUDFLARE_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/annotations/outages"
)

ORGANIZATION_FILE = Path("organizations.json")


# ============================================================
# LOAD ORGANIZATION CATALOG
# ============================================================

def load_organizations():

    if not ORGANIZATION_FILE.exists():

        print()
        print("ERROR:")
        print("organizations.json was not found.")
        print()
        print(
            "Make sure organizations.json exists "
            "in the repository."
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
        print("organizations.json contains invalid JSON.")
        print()
        print(error)

        sys.exit(1)

    organizations = data.get(
        "organizations",
        {}
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
        f"organizations from organizations.json."
    )

    return organizations


# ============================================================
# CLOUDFLARE RADAR
# ============================================================

def get_outages():

    print()
    print("Connecting to Cloudflare Radar...")

    token = os.environ.get(
        "CLOUDFLARE_API_TOKEN",
        "",
    ).strip()

    if not token:

        print()
        print("ERROR:")
        print(
            "CLOUDFLARE_API_TOKEN "
            "was not found."
        )

        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent":
            "global-infrastructure-monitor/2.0",
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

    result = data.get(
        "result",
        {},
    )

    return result.get(
        "annotations",
        [],
    )


# ============================================================
# NORMALIZE CLOUDFLARE EVENT
# ============================================================

def normalize_event(raw_event):

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
            str(location)
            for location in locations
        )

    else:

        location_text = str(
            locations
        )

    if isinstance(asns, list):

        asn_text = ", ".join(
            str(asn)
            for asn in asns
        )

    else:

        asn_text = str(
            asns
        )

    description = (
        raw_event.get("description")
        or "No description provided"
    )

    scope = (
        raw_event.get("scope")
        or "Unknown"
    )

    outage_type = (
        outage.get("outageType")
        or "Unknown"
    )

    cause = (
        outage.get("outageCause")
        or "Unknown"
    )

    event_type = (
        raw_event.get("eventType")
        or "OUTAGE"
    )

    started = (
        raw_event.get("startDate")
        or "Unknown"
    )

    ended = raw_event.get(
        "endDate"
    )

    status = (
        "RESOLVED"
        if ended
        else "ONGOING"
    )

    return {
        "locations":
            location_text or "Unknown",

        "asns":
            asn_text or "Unknown",

        "description":
            description,

        "scope":
            scope,

        "outage_type":
            outage_type,

        "cause":
            cause,

        "event_type":
            event_type,

        "started":
            started,

        "ended":
            ended or "ONGOING",

        "status":
            status,

        "source_url":
            raw_event.get(
                "linkedUrl"
            ) or "",
    }


# ============================================================
# CREATE SEARCHABLE EVENT TEXT
# ============================================================

def create_searchable_text(event):

    fields = [
        event["description"],
        event["scope"],
        event["locations"],
        event["asns"],
        event["outage_type"],
        event["cause"],
        event["event_type"],
    ]

    return " ".join(
        str(field)
        for field in fields
        if field
    ).lower()


# ============================================================
# ALIAS MATCHING
# ============================================================

def alias_matches(text, alias):

    """
    Performs case-insensitive whole-word/phrase matching.

    Using boundaries helps prevent accidental substring matches.

    Examples:

      "Microsoft" matches:
          "Microsoft 365 outage"

      But a short alias should not match merely because
      its letters appear inside another word.
    """

    alias = alias.strip()

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


# ============================================================
# FIND ORGANIZATIONS
# ============================================================

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
# FIND UNIQUE SECTORS
# ============================================================

def identify_sectors(
    organization_matches,
):

    sectors = {
        organization["sector"]

        for organization
        in organization_matches
    }

    return sorted(
        sectors
    )


# ============================================================
# DISPLAY EVENT
# ============================================================

def display_event(
    event_number,
    event,
    organization_matches,
    sectors,
):

    print()
    print("=" * 70)

    print(
        f"Event #{event_number}"
    )

    print("=" * 70)

    print(
        f"Status:       {event['status']}"
    )

    print(
        f"Started:      {event['started']}"
    )

    print(
        f"Ended:        {event['ended']}"
    )

    print(
        f"Location:     {event['locations']}"
    )

    print(
        f"ASN:          {event['asns']}"
    )

    print(
        f"Event type:   {event['event_type']}"
    )

    print(
        f"Outage type:  {event['outage_type']}"
    )

    print(
        f"Cause:        {event['cause']}"
    )

    print(
        f"Scope:        {event['scope']}"
    )

    print()
    print("Description:")

    print(
        event["description"]
    )

    print()
    print("Organizations detected:")

    if not organization_matches:

        print(
            "  None"
        )

    else:

        for organization in organization_matches:

            print(
                f"  - "
                f"{organization['display_name']}"
            )

            print(
                f"      ID: "
                f"{organization['id']}"
            )

            print(
                f"      Sector: "
                f"{organization['sector']}"
            )

            print(
                f"      Criticality: "
                f"{organization['criticality']}"
            )

            print(
                "      Matched aliases: "
                + ", ".join(
                    organization[
                        "matched_aliases"
                    ]
                )
            )

    print()
    print("Sectors detected:")

    if not sectors:

        print(
            "  None"
        )

    else:

        for sector in sectors:

            print(
                f"  - {sector}"
            )

    print()

    print(
        "Distinct organizations: "
        f"{len(organization_matches)}"
    )

    print(
        "Distinct sectors:       "
        f"{len(sectors)}"
    )

    if event["source_url"]:

        print()

        print(
            "Source:"
        )

        print(
            event["source_url"]
        )


# ============================================================
# BUILT-IN MATCHING TESTS
# ============================================================

def run_matching_tests(
    organizations,
):

    print()
    print("=" * 70)

    print(
        " ORGANIZATION MATCHING SELF-TEST"
    )

    print("=" * 70)

    test_cases = [

        {
            "description":
                "Microsoft 365 and Outlook "
                "are experiencing a global disruption.",

            "expected":
                ["microsoft"],
        },

        {
            "description":
                "Bank of America and Wells Fargo "
                "customers are reporting problems.",

            "expected":
                [
                    "bank_of_america",
                    "wells_fargo",
                ],
        },

        {
            "description":
                "Apple iCloud and the App Store "
                "are unavailable for some users.",

            "expected":
                ["apple"],
        },

        {
            "description":
                "AWS is experiencing elevated "
                "errors in several services.",

            "expected":
                ["amazon"],
        },

        {
            "description":
                "The traveler needs a visa "
                "before entering the country.",

            "expected":
                [],
        },

    ]

    all_tests_passed = True

    for number, test_case in enumerate(
        test_cases,
        start=1,
    ):

        fake_event = {

            "description":
                test_case["description"],

            "scope":
                "Unknown",

            "locations":
                "Unknown",

            "asns":
                "Unknown",

            "outage_type":
                "Unknown",

            "cause":
                "Unknown",

            "event_type":
                "TEST",
        }

        matches = identify_organizations(
            fake_event,
            organizations,
        )

        detected_ids = sorted(
            organization["id"]
            for organization in matches
        )

        expected_ids = sorted(
            test_case["expected"]
        )

        passed = (
            detected_ids
            ==
            expected_ids
        )

        if not passed:

            all_tests_passed = False

        print()

        print(
            f"Test #{number}: "
            f"{'PASS' if passed else 'FAIL'}"
        )

        print(
            "Text:"
        )

        print(
            f"  {test_case['description']}"
        )

        print(
            "Expected:"
        )

        print(
            "  "
            + (
                ", ".join(expected_ids)
                if expected_ids
                else "None"
            )
        )

        print(
            "Detected:"
        )

        print(
            "  "
            + (
                ", ".join(detected_ids)
                if detected_ids
                else "None"
            )
        )

    print()

    if all_tests_passed:

        print(
            "All organization matching "
            "self-tests PASSED."
        )

    else:

        print(
            "WARNING:"
        )

        print(
            "One or more organization matching "
            "self-tests FAILED."
        )

    return all_tests_passed


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)

    print(
        " GLOBAL INFRASTRUCTURE MONITOR"
    )

    print(
        " ORGANIZATION MATCHING DRY RUN"
    )

    print("=" * 70)

    print()

    print(
        "EMAIL DELIVERY: DISABLED"
    )

    print(
        "PRODUCTION STATE CHANGES: DISABLED"
    )

    print(
        "CORRELATION ALERTING: DISABLED"
    )

    print()

    organizations = (
        load_organizations()
    )


    # --------------------------------------------------------
    # FIRST RUN LOCAL MATCHING TESTS
    # --------------------------------------------------------

    tests_passed = (
        run_matching_tests(
            organizations
        )
    )

    if not tests_passed:

        print()
        print(
            "Stopping because matching "
            "self-tests failed."
        )

        sys.exit(1)


    # --------------------------------------------------------
    # GET REAL CLOUDFLARE EVENTS
    # --------------------------------------------------------

    outages = get_outages()

    print()

    print(
        f"Cloudflare returned "
        f"{len(outages)} outage event(s)."
    )


    # --------------------------------------------------------
    # TRACK TOTALS
    # --------------------------------------------------------

    total_organization_matches = 0

    detected_organizations = set()

    detected_sectors = set()


    # --------------------------------------------------------
    # PROCESS EACH EVENT
    # --------------------------------------------------------

    for event_number, raw_event in enumerate(
        outages,
        start=1,
    ):

        event = normalize_event(
            raw_event
        )

        organization_matches = (
            identify_organizations(
                event,
                organizations,
            )
        )

        sectors = (
            identify_sectors(
                organization_matches
            )
        )

        total_organization_matches += (
            len(
                organization_matches
            )
        )

        for organization in organization_matches:

            detected_organizations.add(
                organization["id"]
            )

        for sector in sectors:

            detected_sectors.add(
                sector
            )

        display_event(
            event_number,
            event,
            organization_matches,
            sectors,
        )


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print()
    print("=" * 70)

    print(
        " ORGANIZATION MATCHING DRY RUN SUMMARY"
    )

    print("=" * 70)

    print()

    print(
        f"Cloudflare events:             "
        f"{len(outages)}"
    )

    print(
        f"Organization matches:          "
        f"{total_organization_matches}"
    )

    print(
        f"Distinct organizations:        "
        f"{len(detected_organizations)}"
    )

    print(
        f"Distinct sectors:              "
        f"{len(detected_sectors)}"
    )

    print()

    if detected_organizations:

        print(
            "Organizations detected during this run:"
        )

        for organization_id in sorted(
            detected_organizations
        ):

            display_name = (
                organizations[
                    organization_id
                ].get(
                    "display_name",
                    organization_id,
                )
            )

            sector = (
                organizations[
                    organization_id
                ].get(
                    "sector",
                    "unknown",
                )
            )

            print(
                f"  - {display_name} "
                f"({sector})"
            )

    else:

        print(
            "No watched organizations "
            "were detected."
        )

    print()

    if detected_sectors:

        print(
            "Sectors represented:"
        )

        for sector in sorted(
            detected_sectors
        ):

            print(
                f"  - {sector}"
            )

    print()

    print(
        "EMAIL DELIVERY REMAINS DISABLED."
    )

    print(
        "No production incident state "
        "was changed."
    )

    print()

    print(
        "Organization matching dry run "
        "completed successfully."
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()
