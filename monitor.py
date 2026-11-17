import os
import sys
import json
import html
import hashlib
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import requests


# ============================================================
# GLOBAL NETWORK MONITOR
# PRODUCTION EMAIL-ENABLED VERSION
#
# Sends email for:
#   - NEW_ALERT: a new HIGH or CRITICAL incident
#   - ESCALATED: an existing incident that becomes HIGH/CRITICAL
#   - RESOLVED: a previously ongoing incident that ends
#
# Does not send email for:
#   - DUPLICATE
#   - UPDATED
#   - NEW_NO_ALERT
# ============================================================


CLOUDFLARE_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/annotations/outages"
)

STATE_FILE = Path("state.json")

HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80


# ============================================================
# PROVIDERS OF INTEREST
# ============================================================

MAJOR_CLOUD_PROVIDERS = [
    "microsoft",
    "azure",
    "microsoft 365",
    "office 365",
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
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

def get_required_environment_variable(name):
    value = os.environ.get(name, "").strip()

    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is missing."
        )

    return value


# ============================================================
# STATE MANAGEMENT
# ============================================================

def load_state():
    if not STATE_FILE.exists():
        print("No previous state.json found.")
        print("Starting with an empty incident database.")

        return {"events": {}}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            state = json.load(file)

        state.setdefault("events", {})

        print(
            f"Loaded {len(state['events'])} "
            f"previous incident(s) from state.json."
        )

        return state

    except (OSError, json.JSONDecodeError) as error:
        print()
        print("ERROR: state.json could not be read.")
        print(f"Reason: {error}")
        print()
        print(
            "Stopping to prevent loss of incident history "
            "or duplicate notifications."
        )

        sys.exit(1)


def save_state(state):
    temporary_file = Path("state.json.tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(
            state,
            file,
            indent=2,
            sort_keys=True,
        )
        file.write("\n")

    temporary_file.replace(STATE_FILE)

    print()
    print(
        f"Saved {len(state['events'])} "
        f"incident(s) to state.json."
    )


# ============================================================
# HELPERS
# ============================================================

def contains_any(text, terms):
    text = str(text).lower()

    return any(
        term.lower() in text
        for term in terms
    )


def make_searchable_text(event):
    return " ".join([
        event["locations"],
        event["asns"],
        event["description"],
        event["scope"],
        event["outage_type"],
        event["cause"],
        event["event_type"],
    ]).lower()


# ============================================================
# DOWNLOAD OUTAGES
# ============================================================

def get_outages():
    print("Connecting to Cloudflare Radar...")

    token = get_required_environment_variable(
        "CLOUDFLARE_API_TOKEN"
    )

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
            "Cloudflare HTTP status:",
            response.status_code,
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
        print("ERROR: Cloudflare returned invalid JSON.")

        sys.exit(1)

    if data.get("success") is False:
        print()
        print("Cloudflare API reported an error:")
        print(data.get("errors"))

        sys.exit(1)

    result = data.get("result", {})

    return result.get("annotations", [])


# ============================================================
# NORMALIZE EVENT
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
# IDENTIFY A PROVIDER FOR THE EMAIL SUBJECT
# ============================================================

def identify_provider(event):
    searchable_text = make_searchable_text(event)

    provider_names = [
        ("Microsoft 365", ["microsoft 365", "office 365"]),
        ("Microsoft Azure", ["microsoft azure", "azure"]),
        ("Microsoft", ["microsoft"]),
        (
            "Amazon Web Services",
            ["amazon web services", "aws"],
        ),
        ("Google Cloud", ["google cloud"]),
        ("Cloudflare", ["cloudflare"]),
        ("Akamai", ["akamai"]),
        ("Fastly", ["fastly"]),
        ("Verizon", ["verizon"]),
        ("AT&T", ["at&t", " att "]),
        ("Lumen", ["lumen", "level 3", "centurylink"]),
        ("Comcast", ["comcast", "xfinity"]),
        ("Cogent", ["cogent"]),
        ("GTT", ["gtt"]),
        ("Zayo", ["zayo"]),
        ("NTT", ["ntt"]),
        ("Arelion", ["arelion", "telia"]),
    ]

    padded_text = f" {searchable_text} "

    for provider_name, identifiers in provider_names:
        if any(
            identifier in padded_text
            for identifier in identifiers
        ):
            return provider_name

    if event["locations"] != "Unknown":
        return f"Internet outage in {event['locations']}"

    return "Global Internet disruption"


# ============================================================
# INCIDENT FINGERPRINT
# ============================================================

def create_fingerprint(event):
    """
    This must stay consistent with the dry-run version so the
    existing Microsoft incident retains the same incident ID.

    End time and status are deliberately omitted. This allows the
    same incident to transition from ONGOING to RESOLVED.
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
        fingerprint_data.encode("utf-8")
    ).hexdigest()

    return fingerprint[:20]


# ============================================================
# EVENT SCORING
# ============================================================

def calculate_score(event):
    score = 0
    reasons = []

    searchable_text = make_searchable_text(event)
    outage_type = event["outage_type"].lower()
    scope = event["scope"].lower()

    # Outage scope

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

    # Cloud and major service provider

    if contains_any(
        searchable_text,
        MAJOR_CLOUD_PROVIDERS,
    ):
        score += 35
        reasons.append(
            "Major cloud/service provider +35"
        )

    # CDN and DNS provider

    if contains_any(
        searchable_text,
        MAJOR_CDN_DNS_PROVIDERS,
    ):
        score += 30
        reasons.append(
            "Major CDN/DNS provider +30"
        )

    # Network carrier

    if contains_any(
        searchable_text,
        MAJOR_NETWORK_PROVIDERS,
    ):
        score += 25
        reasons.append(
            "Major network/carrier +25"
        )

    # Multiple ASNs

    if (
        event["asns"] != "Unknown"
        and "," in event["asns"]
    ):
        score += 15
        reasons.append(
            "Multiple ASNs affected +15"
        )

    # Ongoing incident

    if event["status"] == "ONGOING":
        score += 10
        reasons.append(
            "Incident currently ongoing +10"
        )

    # Broad or global incident

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

    return min(score, 100), reasons


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


def severity_level(severity):
    levels = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return levels.get(severity, 0)


# ============================================================
# DEDUPLICATION ACTION
# ============================================================

def determine_action(
    event,
    score,
    severity,
    previous_event,
):
    if previous_event is None:
        if severity in ["HIGH", "CRITICAL"]:
            return "NEW_ALERT"

        return "NEW_NO_ALERT"

    previous_status = previous_event.get(
        "status",
        "UNKNOWN",
    )

    previous_severity = previous_event.get(
        "severity",
        "LOW",
    )

    previous_score = int(
        previous_event.get(
            "score",
            0,
        )
    )

    # A previously ongoing incident has ended.

    if (
        previous_status == "ONGOING"
        and event["status"] == "RESOLVED"
    ):
        return "RESOLVED"

    # Severity increased.

    if (
        severity_level(severity)
        > severity_level(previous_severity)
    ):
        return "ESCALATED"

    # Score increased significantly within one severity band.

    if score >= previous_score + 15:
        return "ESCALATED"

    # Nothing alert-worthy changed.

    if (
        event["status"] == previous_status
        and severity == previous_severity
    ):
        return "DUPLICATE"

    return "UPDATED"


# ============================================================
# EMAIL DECISION
# ============================================================

def should_send_email(
    action,
    severity,
    previous_event,
):
    if action == "NEW_ALERT":
        return True

    if (
        action == "ESCALATED"
        and severity in ["HIGH", "CRITICAL"]
    ):
        return True

    if action == "RESOLVED":
        if not previous_event:
            return False

        previous_severity = previous_event.get(
            "severity",
            "LOW",
        )

        # Send recovery notices only for incidents that had
        # reached the email-alert threshold.

        return previous_severity in [
            "HIGH",
            "CRITICAL",
        ]

    return False


# ============================================================
# EMAIL CONTENT
# ============================================================

def build_email(
    incident_id,
    event,
    score,
    severity,
    reasons,
    action,
):
    provider = identify_provider(event)

    if action == "RESOLVED":
        subject = (
            f"[GLOBAL NETWORK - RESOLVED] "
            f"{provider}"
        )

    elif action == "ESCALATED":
        subject = (
            f"[GLOBAL NETWORK - {severity}] "
            f"ESCALATED: {provider}"
        )

    else:
        subject = (
            f"[GLOBAL NETWORK - {severity}] "
            f"{provider}"
        )

    reason_lines = "\n".join(
        f"- {reason}"
        for reason in reasons
    )

    if not reason_lines:
        reason_lines = "- No additional scoring rules matched"

    source_text = (
        event["source_url"]
        if event["source_url"]
        else "Cloudflare Radar"
    )

    plain_body = f"""GLOBAL NETWORK DISRUPTION

Alert Type: {action}
Severity: {severity}
Score: {score}/100
Status: {event['status']}

Provider:
{provider}

Location:
{event['locations']}

ASN:
{event['asns']}

Event Type:
{event['event_type']}

Outage Type:
{event['outage_type']}

Cause:
{event['cause']}

Scope:
{event['scope']}

Description:
{event['description']}

Started:
{event['started']}

Ended:
{event['ended']}

Why this event scored {score}:
{reason_lines}

Incident ID:
{incident_id}

Source:
{source_text}
"""

    severity_colors = {
        "CRITICAL": "#b91c1c",
        "HIGH": "#c2410c",
        "MEDIUM": "#a16207",
        "LOW": "#166534",
    }

    if action == "RESOLVED":
        header_color = "#166534"
    else:
        header_color = severity_colors.get(
            severity,
            "#334155",
        )

    safe_provider = html.escape(provider)
    safe_action = html.escape(action)
    safe_severity = html.escape(severity)
    safe_status = html.escape(event["status"])
    safe_location = html.escape(event["locations"])
    safe_asns = html.escape(event["asns"])
    safe_event_type = html.escape(event["event_type"])
    safe_outage_type = html.escape(event["outage_type"])
    safe_cause = html.escape(event["cause"])
    safe_scope = html.escape(event["scope"])
    safe_description = html.escape(event["description"])
    safe_started = html.escape(event["started"])
    safe_ended = html.escape(event["ended"])
    safe_incident_id = html.escape(incident_id)

    reason_items = "".join(
        f"<li>{html.escape(reason)}</li>"
        for reason in reasons
    )

    if not reason_items:
        reason_items = (
            "<li>No additional scoring rules matched</li>"
        )

    if event["source_url"]:
        safe_source_url = html.escape(
            event["source_url"],
            quote=True,
        )

        source_html = (
            f'<a href="{safe_source_url}">'
            "View source information"
            "</a>"
        )
    else:
        source_html = "Cloudflare Radar"

    html_body = f"""
    <html>
      <body style="
        background:#f3f4f6;
        color:#1f2937;
        font-family:Arial,sans-serif;
        margin:0;
        padding:20px;
      ">
        <div style="
          background:#ffffff;
          border:1px solid #d1d5db;
          border-radius:10px;
          margin:auto;
          max-width:720px;
          overflow:hidden;
        ">
          <div style="
            background:{header_color};
            color:#ffffff;
            padding:20px 24px;
          ">
            <h2 style="margin:0;">
              Global Network Disruption
            </h2>

            <p style="margin:8px 0 0 0;">
              {safe_provider}
            </p>
          </div>

          <div style="padding:24px;">
            <table style="
              border-collapse:collapse;
              width:100%;
            ">
              <tr>
                <td style="padding:6px 0;">
                  <strong>Alert type</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_action}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Severity</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_severity}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Score</strong>
                </td>
                <td style="padding:6px 0;">
                  {score}/100
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Status</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_status}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Location</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_location}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>ASN</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_asns}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Event type</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_event_type}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Outage type</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_outage_type}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Cause</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_cause}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Started</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_started}
                </td>
              </tr>

              <tr>
                <td style="padding:6px 0;">
                  <strong>Ended</strong>
                </td>
                <td style="padding:6px 0;">
                  {safe_ended}
                </td>
              </tr>
            </table>

            <h3>Description</h3>
            <p>{safe_description}</p>

            <h3>Scope</h3>
            <p>{safe_scope}</p>

            <h3>Why this event scored {score}</h3>
            <ul>{reason_items}</ul>

            <p>
              <strong>Incident ID:</strong>
              {safe_incident_id}
            </p>

            <p>
              <strong>Source:</strong>
              {source_html}
            </p>
          </div>
        </div>
      </body>
    </html>
    """

    return subject, plain_body, html_body


# ============================================================
# SEND EMAIL
# ============================================================

def send_email(
    subject,
    plain_body,
    html_body,
):
    smtp_host = get_required_environment_variable(
        "SMTP_HOST"
    )

    smtp_port_text = get_required_environment_variable(
        "SMTP_PORT"
    )

    smtp_username = get_required_environment_variable(
        "SMTP_USERNAME"
    )

    smtp_password = get_required_environment_variable(
        "SMTP_PASSWORD"
    )

    alert_from = get_required_environment_variable(
        "ALERT_FROM"
    )

    alert_to = get_required_environment_variable(
        "ALERT_TO"
    )

    try:
        smtp_port = int(smtp_port_text)

    except ValueError as error:
        raise RuntimeError(
            "SMTP_PORT must be a number."
        ) from error

    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = alert_from
    message["To"] = alert_to

    message.set_content(plain_body)

    message.add_alternative(
        html_body,
        subtype="html",
    )

    print(
        f"Connecting to SMTP server "
        f"{smtp_host}:{smtp_port}..."
    )

    with smtplib.SMTP(
        smtp_host,
        smtp_port,
        timeout=30,
    ) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()

        print("Authenticating with email provider...")

        smtp.login(
            smtp_username,
            smtp_password,
        )

        print(f"Sending email: {subject}")

        smtp.send_message(message)

    print("Email sent successfully.")


# ============================================================
# DISPLAY EVENT IN ACTIONS LOG
# ============================================================

def display_event(
    event_number,
    incident_id,
    event,
    score,
    severity,
    reasons,
    action,
    email_sent,
):
    print()
    print("=" * 65)
    print(f"Event #{event_number}")
    print("=" * 65)

    print(f"Incident ID:   {incident_id}")
    print(f"Severity:      {severity}")
    print(f"Score:         {score}/100")
    print(f"Status:        {event['status']}")
    print(f"Dedup action:  {action}")
    print(f"Email sent:    {'YES' if email_sent else 'NO'}")
    print(f"Location:      {event['locations']}")
    print(f"ASN:           {event['asns']}")
    print(f"Started:       {event['started']}")
    print(f"Ended:         {event['ended']}")
    print(f"Outage type:   {event['outage_type']}")
    print(f"Cause:         {event['cause']}")
    print(f"Scope:         {event['scope']}")

    print()
    print("Description:")
    print(event["description"])

    print()
    print("Scoring:")

    if reasons:
        for reason in reasons:
            print(f"  + {reason}")
    else:
        print("  No scoring rules matched.")

    print()

    if email_sent:
        print(">>> EMAIL ALERT SENT <<<")
    elif action == "DUPLICATE":
        print("Duplicate incident suppressed.")
    elif action == "NEW_NO_ALERT":
        print("New incident is below the email threshold.")
    else:
        print("No email was required.")

    if event["source_url"]:
        print()
        print(f"Source: {event['source_url']}")


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
    email_sent,
):
    existing = state["events"].get(
        incident_id,
        {},
    )

    now = current_time()

    first_seen = (
        existing.get("first_seen")
        or now
    )

    alert_count = int(
        existing.get(
            "alert_count",
            0,
        )
    )

    last_alerted = existing.get(
        "last_alerted"
    )

    if email_sent:
        alert_count += 1
        last_alerted = now

    state["events"][incident_id] = {
        "first_seen": first_seen,
        "last_seen": now,
        "last_alerted": last_alerted,
        "started": event["started"],
        "ended": event["ended"],
        "status": event["status"],
        "score": score,
        "severity": severity,
        "location": event["locations"],
        "asns": event["asns"],
        "description": event["description"],
        "last_action": action,
        "alert_count": alert_count,
    }


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("=" * 65)
    print(" GLOBAL NETWORK MONITOR")
    print(" PRODUCTION EMAIL DELIVERY ENABLED")
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

    stats = {
        "NEW_ALERT": 0,
        "NEW_NO_ALERT": 0,
        "DUPLICATE": 0,
        "ESCALATED": 0,
        "RESOLVED": 0,
        "UPDATED": 0,
    }

    emails_sent = 0

    for event_number, raw_event in enumerate(
        outages,
        start=1,
    ):
        event = normalize_event(raw_event)

        incident_id = create_fingerprint(event)

        score, reasons = calculate_score(event)

        severity = determine_severity(score)

        previous_event = state["events"].get(
            incident_id
        )

        action = determine_action(
            event,
            score,
            severity,
            previous_event,
        )

        stats[action] += 1

        email_sent = False

        if should_send_email(
            action,
            severity,
            previous_event,
        ):
            subject, plain_body, html_body = build_email(
                incident_id,
                event,
                score,
                severity,
                reasons,
                action,
            )

            try:
                send_email(
                    subject,
                    plain_body,
                    html_body,
                )

                email_sent = True
                emails_sent += 1

            except Exception as error:
                print()
                print(
                    "ERROR: The qualifying incident email "
                    "could not be sent."
                )
                print(f"Reason: {error}")
                print()
                print(
                    "state.json will not be updated, so the "
                    "monitor can retry during the next run."
                )

                sys.exit(1)

        update_state(
            state,
            incident_id,
            event,
            score,
            severity,
            action,
            email_sent,
        )

        display_event(
            event_number,
            incident_id,
            event,
            score,
            severity,
            reasons,
            action,
            email_sent,
        )

    save_state(state)

    print()
    print("=" * 65)
    print(" PRODUCTION RUN SUMMARY")
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
    print(f"Emails sent:            {emails_sent}")
    print()
    print(
        "Global Network Monitor completed successfully."
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
