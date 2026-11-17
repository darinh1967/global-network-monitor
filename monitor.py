import os
import sys
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import requests


# ============================================================
# GLOBAL NETWORK MONITOR
# DEDUPLICATION DRY-RUN VERSION
#
# This version DOES NOT send email.
#
# It:
#   1. Connects to Cloudflare Radar
#   2. Retrieves recent Internet outage events
#   3. Scores each event from 0-100
#   4. Classifies LOW/MEDIUM/HIGH/CRITICAL
#   5. Creates a unique fingerprint for each incident
#   6. Remembers incidents in state.json
#   7. Detects new, duplicate, escalated, and resolved events
#   8. Shows whether an email WOULD be sent
# ============================================================


CLOUDFLARE_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/annotations/outages"
)

STATE_FILE = Path("state.json")

HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80


# ============================================================
# PROVIDERS WE CARE ABOUT
# ============================================================

MAJOR_CLOUD_PROVIDERS = [
    "microsoft",
    "azure",
    "microsoft 365",
    "amazon",
    "aws",
    "amazon web services",
    "google cloud",
    "google",
]

MAJOR_CDN_DNS_PROVIDERS = [
    "cloudflare",
    "akamai",
    "fastly",
]

MAJOR_NETWORK_PROVIDERS = [
    "verizon",
    "at&t",
    "att",
    "lumen",
    "level 3",
    "centurylink",
    "comcast",
    "xfinity",
    "cogent",
    "gtt",
    "zayo",
    "ntt",
    "telia",
    "arelion",
]


# ============================================================
# TIME
# ============================================================

def current_time():

    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# STATE MANAGEMENT
# ============================================================

def load_state():

    if not STATE_FILE.exists():

        print(
            "No previous state.json found."
        )

        print(
            "Starting with an empty incident database."
        )

        return {
            "events": {}
        }

    try:

        with STATE_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            state = json.load(file)

        state.setdefault(
            "events",
            {}
        )

        print(
            f"Loaded {len(state['events'])} "
            f"previous incident(s) from state.json."
        )

        return state

    except Exception as error:

        print()
        print("WARNING:")
        print(
            "state.json could not be read."
        )

        print(
            f"Reason: {error}"
        )

        print(
            "Starting with an empty incident database."
        )

        return {
            "events": {}
        }


def save_state(state):

    temporary_file = Path(
        "state.json.tmp"
    )

    with temporary_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            state,
            file,
            indent=2,
            sort_keys=True,
        )

        file.write("\n")

    temporary_file.replace(
        STATE_FILE
    )

    print()
    print(
        f"Saved {len(state['events'])} "
        f"incident(s) to state.json."
    )


# ============================================================
# HELPER
# ============================================================

def contains_any(text, terms):

    text = str(text).lower()

    return any(
        term.lower() in text
        for term in terms
    )


# ============================================================
# DOWNLOAD OUTAGES
# ============================================================

def get_outages():

    print(
        "Connecting to Cloudflare Radar..."
    )

    token = os.environ.get(
        "CLOUDFLARE_API_TOKEN",
        ""
    ).strip()

    if not token:

        print()
        print(
            "ERROR: CLOUDFLARE_API_TOKEN "
            "was not found."
        )

        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent":
            "global-network-monitor/1.0",
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
            response.status_code
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
        {}
    )

    return result.get(
        "annotations",
        []
    )


# ============================================================
# NORMALIZE EVENT
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

    if isinstance(
        locations,
        list
    ):

        location_text = ", ".join(
            str(location)
            for location in locations
        )

    else:

        location_text = str(
            locations
        )

    if isinstance(
        asns,
        list
    ):

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
# CREATE INCIDENT FINGERPRINT
# ============================================================

def create_fingerprint(event):

    """
    Creates a stable ID for an incident.

    IMPORTANT:

    We deliberately DO NOT include end time or current
    status in the fingerprint.

    Otherwise the same incident would receive a new ID
    when it changed from ONGOING to RESOLVED.
    """

    fingerprint_data = "|".join([
        event["started"],
        event["event_type"],
        event["outage_type"],
        event["locations"],
        event["asns"],
        event["description"],
    ])

    fingerprint = hashlib.sha256(
        fingerprint_data.encode(
            "utf-8"
        )
    ).hexdigest()

    return fingerprint[:20]


# ============================================================
# SCORE EVENT
# ============================================================

def calculate_score(event):

    score = 0

    reasons = []

    searchable_text = " ".join([
        event["locations"],
        event["asns"],
        event["description"],
        event["scope"],
        event["outage_type"],
        event["cause"],
        event["event_type"],
    ]).lower()

    outage_type = (
        event["outage_type"]
        .lower()
    )

    scope = (
        event["scope"]
        .lower()
    )


    # --------------------------------------------------------
    # OUTAGE SCOPE
    # --------------------------------------------------------

    if (
        "national" in outage_type
        or "nationwide" in searchable_text
        or "countrywide" in searchable_text
    ):

        score += 50

        reasons.append(
            "Nationwide/national outage +50"
        )

    elif (
        "multiple regions" in scope
        or "multiple cities" in scope
        or "multiple regions" in searchable_text
        or "multiple cities" in searchable_text
    ):

        score += 30

        reasons.append(
            "Multiple regions/cities affected +30"
        )

    elif "regional" in outage_type:

        score += 20

        reasons.append(
            "Regional outage +20"
        )


    # --------------------------------------------------------
    # CLOUD PROVIDER
    # --------------------------------------------------------

    if contains_any(
        searchable_text,
        MAJOR_CLOUD_PROVIDERS
    ):

        score += 35

        reasons.append(
            "Major cloud/service provider +35"
        )


    # --------------------------------------------------------
    # CDN / DNS
    # --------------------------------------------------------

    if contains_any(
        searchable_text,
        MAJOR_CDN_DNS_PROVIDERS
    ):

        score += 30

        reasons.append(
            "Major CDN/DNS provider +30"
        )


    # --------------------------------------------------------
    # NETWORK CARRIER
    # --------------------------------------------------------

    if contains_any(
        searchable_text,
        MAJOR_NETWORK_PROVIDERS
    ):

        score += 25

        reasons.append(
            "Major network/carrier +25"
        )


    # --------------------------------------------------------
    # MULTIPLE ASNs
    # --------------------------------------------------------

    if (
        event["asns"] != "Unknown"
        and "," in event["asns"]
    ):

        score += 15

        reasons.append(
            "Multiple ASNs affected +15"
        )


    # --------------------------------------------------------
    # ONGOING
    # --------------------------------------------------------

    if event["status"] == "ONGOING":

        score += 10

        reasons.append(
            "Incident currently ongoing +10"
        )


    # --------------------------------------------------------
    # GLOBAL / BROAD EFFECT
    # --------------------------------------------------------

    broad_terms = [
        "global",
        "multiple countries",
        "several countries",
        "international",
    ]

    if contains_any(
        searchable_text,
        broad_terms
    ):

        score += 20

        reasons.append(
            "Broad/global impact +20"
        )


    score = min(
        score,
        100
    )

    return score, reasons


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(score):

    if score >= CRITICAL_THRESHOLD:

        return "CRITICAL"

    if score >= HIGH_THRESHOLD:

        return "HIGH"

    if score >= 40:

        return "MEDIUM"

    return "LOW"


# ============================================================
# NUMBER USED FOR ESCALATION COMPARISON
# ============================================================

def severity_level(severity):

    levels = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return levels.get(
        severity,
        0
    )


# ============================================================
# DETERMINE INCIDENT ACTION
# ============================================================

def determine_action(
    event,
    score,
    severity,
    previous_event,
):

    """
    Possible return values:

    NEW_ALERT
    NEW_NO_ALERT
    DUPLICATE
    ESCALATED
    RESOLVED
    UPDATED
    """

    # --------------------------------------------------------
    # WE HAVE NEVER SEEN THIS INCIDENT
    # --------------------------------------------------------

    if previous_event is None:

        if severity in [
            "HIGH",
            "CRITICAL"
        ]:

            return "NEW_ALERT"

        return "NEW_NO_ALERT"


    previous_status = (
        previous_event.get(
            "status",
            "UNKNOWN"
        )
    )

    previous_severity = (
        previous_event.get(
            "severity",
            "LOW"
        )
    )

    previous_score = int(
        previous_event.get(
            "score",
            0
        )
    )


    # --------------------------------------------------------
    # INCIDENT HAS RESOLVED
    # --------------------------------------------------------

    if (
        previous_status == "ONGOING"
        and event["status"] == "RESOLVED"
    ):

        return "RESOLVED"


    # --------------------------------------------------------
    # SEVERITY HAS MOVED UP
    # --------------------------------------------------------

    if (
        severity_level(severity)
        >
        severity_level(
            previous_severity
        )
    ):

        return "ESCALATED"


    # --------------------------------------------------------
    # SCORE JUMPED SUBSTANTIALLY
    # --------------------------------------------------------

    if (
        score
        >=
        previous_score + 15
    ):

        return "ESCALATED"


    # --------------------------------------------------------
    # NOTHING IMPORTANT CHANGED
    # --------------------------------------------------------

    if (
        event["status"]
        ==
        previous_status

        and

        severity
        ==
        previous_severity
    ):

        return "DUPLICATE"


    return "UPDATED"


# ============================================================
# WOULD WE SEND EMAIL?
# ============================================================

def would_send_email(
    action,
    severity,
):

    if action == "NEW_ALERT":

        return True

    if (
        action == "ESCALATED"
        and severity in [
            "HIGH",
            "CRITICAL",
        ]
    ):

        return True

    if action == "RESOLVED":

        return True

    return False


# ============================================================
# DISPLAY EVENT
# ============================================================

def display_event(
    event_number,
    incident_id,
    event,
    score,
    severity,
    reasons,
    action,
):

    print()
    print("=" * 65)

    print(
        f"Event #{event_number}"
    )

    print("=" * 65)

    print(
        f"Incident ID:   {incident_id}"
    )

    print(
        f"Severity:      {severity}"
    )

    print(
        f"Score:         {score}/100"
    )

    print(
        f"Status:        {event['status']}"
    )

    print(
        f"Dedup action:  {action}"
    )

    print(
        f"Location:      {event['locations']}"
    )

    print(
        f"ASN:           {event['asns']}"
    )

    print(
        f"Started:       {event['started']}"
    )

    print(
        f"Ended:         {event['ended']}"
    )

    print(
        f"Outage type:   {event['outage_type']}"
    )

    print(
        f"Cause:         {event['cause']}"
    )

    print(
        f"Scope:         {event['scope']}"
    )

    print()
    print(
        "Description:"
    )

    print(
        event["description"]
    )

    print()
    print(
        "Scoring:"
    )

    if reasons:

        for reason in reasons:

            print(
                f"  + {reason}"
            )

    else:

        print(
            "  No scoring rules matched."
        )

    print()

    if would_send_email(
        action,
        severity,
    ):

        print(
            ">>> WOULD SEND EMAIL <<<"
        )

    else:

        print(
            "No email would be sent."
        )

    if event["source_url"]:

        print()

        print(
            f"Source: {event['source_url']}"
        )


# ============================================================
# UPDATE STATE
# ============================================================

def update_state(
    state,
    incident_id,
    event,
    score,
    severity,
    action,
):

    existing = (
        state["events"]
        .get(
            incident_id,
            {}
        )
    )

    now = current_time()

    first_seen = (
        existing.get(
            "first_seen"
        )
        or now
    )

    alert_count = int(
        existing.get(
            "alert_count",
            0
        )
    )

    if would_send_email(
        action,
        severity,
    ):

        alert_count += 1

    state["events"][
        incident_id
    ] = {

        "first_seen":
            first_seen,

        "last_seen":
            now,

        "started":
            event["started"],

        "ended":
            event["ended"],

        "status":
            event["status"],

        "score":
            score,

        "severity":
            severity,

        "location":
            event["locations"],

        "asns":
            event["asns"],

        "description":
            event["description"],

        "alert_count":
            alert_count,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 65)
    print(
        " GLOBAL NETWORK MONITOR"
    )
    print(
        " DEDUPLICATION DRY RUN - EMAIL DISABLED"
    )
    print("=" * 65)
    print()

    state = load_state()

    print()

    outages = get_outages()

    print()

    print(
        f"Cloudflare returned "
        f"{len(outages)} outage event(s)."
    )


    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    stats = {
        "NEW_ALERT": 0,
        "NEW_NO_ALERT": 0,
        "DUPLICATE": 0,
        "ESCALATED": 0,
        "RESOLVED": 0,
        "UPDATED": 0,
    }

    emails_that_would_send = 0


    # --------------------------------------------------------
    # PROCESS EVENTS
    # --------------------------------------------------------

    for event_number, raw_event in enumerate(
        outages,
        start=1,
    ):

        event = normalize_event(
            raw_event
        )

        incident_id = (
            create_fingerprint(
                event
            )
        )

        score, reasons = (
            calculate_score(
                event
            )
        )

        severity = (
            determine_severity(
                score
            )
        )

        previous_event = (
            state["events"]
            .get(
                incident_id
            )
        )

        action = (
            determine_action(
                event,
                score,
                severity,
                previous_event,
            )
        )

        stats[action] += 1

        if would_send_email(
            action,
            severity,
        ):

            emails_that_would_send += 1

        display_event(
            event_number,
            incident_id,
            event,
            score,
            severity,
            reasons,
            action,
        )

        update_state(
            state,
            incident_id,
            event,
            score,
            severity,
            action,
        )


    # --------------------------------------------------------
    # SAVE NEW INCIDENT DATABASE
    # --------------------------------------------------------

    save_state(
        state
    )


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print("=" * 65)
    print(
        " DEDUPLICATION DRY RUN SUMMARY"
    )
    print("=" * 65)

    print()

    print(
        f"Events returned:        "
        f"{len(outages)}"
    )

    print(
        f"New alert events:       "
        f"{stats['NEW_ALERT']}"
    )

    print(
        f"New events below limit: "
        f"{stats['NEW_NO_ALERT']}"
    )

    print(
        f"Duplicate events:       "
        f"{stats['DUPLICATE']}"
    )

    print(
        f"Escalated events:       "
        f"{stats['ESCALATED']}"
    )

    print(
        f"Resolved events:        "
        f"{stats['RESOLVED']}"
    )

    print(
        f"Other updates:          "
        f"{stats['UPDATED']}"
    )

    print()

    print(
        "Emails that WOULD have been sent: "
        f"{emails_that_would_send}"
    )

    print()

    print(
        "EMAIL DELIVERY IS DISABLED."
    )

    print(
        "This was a deduplication dry run only."
    )

    print()

    print(
        "Global Network Monitor completed successfully."
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()
