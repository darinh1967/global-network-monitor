import os
import sys
import requests


# ============================================================
# GLOBAL NETWORK MONITOR - DRY RUN VERSION
#
# This version DOES NOT send email.
#
# It:
#   1. Connects to Cloudflare Radar
#   2. Retrieves recent Internet outage events
#   3. Scores each event from 0-100
#   4. Classifies the event as LOW/MEDIUM/HIGH/CRITICAL
#   5. Shows whether an email WOULD be sent
# ============================================================


CLOUDFLARE_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/annotations/outages"
)


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
# SCORING THRESHOLDS
# ============================================================

HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80


# ============================================================
# HELPER FUNCTION
# ============================================================

def contains_any(text, terms):
    """
    Returns True if any term occurs in the supplied text.
    """

    text = str(text).lower()

    return any(
        term.lower() in text
        for term in terms
    )


# ============================================================
# DOWNLOAD OUTAGES FROM CLOUDFLARE RADAR
# ============================================================

def get_outages():

    print("Connecting to Cloudflare Radar...")

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()

    if not token:
        print()
        print("ERROR:")
        print("CLOUDFLARE_API_TOKEN was not found.")
        print()
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "global-network-monitor/1.0",
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
            f"Cloudflare HTTP status: "
            f"{response.status_code}"
        )

        response.raise_for_status()

    except requests.exceptions.RequestException as error:

        print()
        print("ERROR connecting to Cloudflare Radar:")
        print(error)

        sys.exit(1)

    try:

        data = response.json()

    except ValueError:

        print()
        print("ERROR:")
        print("Cloudflare returned invalid JSON.")

        sys.exit(1)

    if data.get("success") is False:

        print()
        print("Cloudflare API reported an error:")
        print(data.get("errors"))

        sys.exit(1)

    result = data.get("result", {})

    outages = result.get("annotations", [])

    return outages


# ============================================================
# NORMALIZE CLOUDFLARE EVENT
# ============================================================

def normalize_event(raw_event):

    outage = raw_event.get("outage") or {}

    locations = raw_event.get("locations") or []
    asns = raw_event.get("asns") or []

    if isinstance(locations, list):
        location_text = ", ".join(
            str(location)
            for location in locations
        )
    else:
        location_text = str(locations)

    if isinstance(asns, list):
        asn_text = ", ".join(
            str(asn)
            for asn in asns
        )
    else:
        asn_text = str(asns)

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

    ended = raw_event.get("endDate")

    status = (
        "RESOLVED"
        if ended
        else "ONGOING"
    )

    return {
        "locations": location_text or "Unknown",
        "asns": asn_text or "Unknown",
        "description": description,
        "scope": scope,
        "outage_type": outage_type,
        "cause": cause,
        "event_type": event_type,
        "started": started,
        "ended": ended or "ONGOING",
        "status": status,
        "source_url": raw_event.get("linkedUrl") or "",
    }


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

    outage_type = event["outage_type"].lower()

    scope = event["scope"].lower()


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
    # MAJOR CLOUD PROVIDERS
    # --------------------------------------------------------

    if contains_any(
        searchable_text,
        MAJOR_CLOUD_PROVIDERS,
    ):

        score += 35

        reasons.append(
            "Major cloud/service provider +35"
        )


    # --------------------------------------------------------
    # CDN / DNS PROVIDERS
    # --------------------------------------------------------

    if contains_any(
        searchable_text,
        MAJOR_CDN_DNS_PROVIDERS,
    ):

        score += 30

        reasons.append(
            "Major CDN/DNS provider +30"
        )


    # --------------------------------------------------------
    # MAJOR NETWORK PROVIDERS
    # --------------------------------------------------------

    if contains_any(
        searchable_text,
        MAJOR_NETWORK_PROVIDERS,
    ):

        score += 25

        reasons.append(
            "Major network/carrier +25"
        )


    # --------------------------------------------------------
    # MULTIPLE ASNs
    # --------------------------------------------------------

    asn_text = event["asns"]

    if (
        asn_text != "Unknown"
        and "," in asn_text
    ):

        score += 15

        reasons.append(
            "Multiple ASNs affected +15"
        )


    # --------------------------------------------------------
    # ONGOING EVENT
    # --------------------------------------------------------

    if event["status"] == "ONGOING":

        score += 10

        reasons.append(
            "Incident currently ongoing +10"
        )


    # --------------------------------------------------------
    # BROAD / GLOBAL LANGUAGE
    # --------------------------------------------------------

    broad_terms = [
        "global",
        "multiple countries",
        "several countries",
        "international",
    ]

    if contains_any(
        searchable_text,
        broad_terms,
    ):

        score += 20

        reasons.append(
            "Broad/global impact +20"
        )


    # Never allow a score above 100.

    score = min(score, 100)

    return score, reasons


# ============================================================
# DETERMINE SEVERITY
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
# DETERMINE WHETHER WE WOULD EMAIL
# ============================================================

def would_send_alert(severity):

    return severity in [
        "HIGH",
        "CRITICAL",
    ]


# ============================================================
# DISPLAY EVENT
# ============================================================

def display_event(
    event_number,
    event,
    score,
    severity,
    reasons,
):

    print()
    print("=" * 65)

    print(
        f"Event #{event_number}"
    )

    print("=" * 65)

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
    print("Description:")

    print(
        event["description"]
    )

    print()
    print("Scoring:")

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

    if would_send_alert(severity):

        print(
            ">>> WOULD SEND EMAIL ALERT <<<"
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
# MAIN PROGRAM
# ============================================================

def main():

    print()
    print("=" * 65)
    print(" GLOBAL NETWORK MONITOR")
    print(" DRY RUN - EMAIL DISABLED")
    print("=" * 65)
    print()

    outages = get_outages()

    print()

    print(
        f"Cloudflare returned "
        f"{len(outages)} outage event(s)."
    )

    print()

    if not outages:

        print(
            "No outage events were returned."
        )

        print()

        print(
            "Dry run completed successfully."
        )

        return


    # Statistics for this run.

    counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    alert_count = 0


    # Examine each outage.

    for event_number, raw_event in enumerate(
        outages,
        start=1,
    ):

        event = normalize_event(
            raw_event
        )

        score, reasons = calculate_score(
            event
        )

        severity = determine_severity(
            score
        )

        counts[severity] += 1

        if would_send_alert(severity):
            alert_count += 1

        display_event(
            event_number,
            event,
            score,
            severity,
            reasons,
        )


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print()
    print("=" * 65)
    print(" DRY RUN SUMMARY")
    print("=" * 65)

    print()

    print(
        f"Total events:      {len(outages)}"
    )

    print(
        f"Critical events:   {counts['CRITICAL']}"
    )

    print(
        f"High events:       {counts['HIGH']}"
    )

    print(
        f"Medium events:     {counts['MEDIUM']}"
    )

    print(
        f"Low events:        {counts['LOW']}"
    )

    print()

    print(
        f"Emails that WOULD have been sent: "
        f"{alert_count}"
    )

    print()

    print(
        "EMAIL DELIVERY IS DISABLED."
    )

    print(
        "This was a dry run only."
    )

    print()

    print(
        "Global Network Monitor completed successfully."
    )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":
    main()
