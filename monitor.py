import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

# Persistent-correlation dry run. No email is sent.
CLOUDFLARE_URL = "https://api.cloudflare.com/client/v4/radar/annotations/outages"
ORGANIZATION_FILE = Path("organizations.json")
STATE_FILE = Path("correlation-state.json")
SAME_SECTOR_WINDOW_MINUTES = 60
CROSS_SECTOR_WINDOW_MINUTES = 45
HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80
MINIMUM_EMAIL_CONFIDENCE = 50


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def parse_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_datetime(value):
    parsed = parse_datetime(value)
    return parsed.isoformat() if parsed else "Unknown"


def minutes_between(first, second):
    first_dt = parse_datetime(first)
    second_dt = parse_datetime(second)
    if not first_dt or not second_dt:
        return None
    return abs((second_dt - first_dt).total_seconds()) / 60


def load_json(path, name):
    if not path.exists():
        print(f"ERROR: {name} was not found.")
        sys.exit(1)
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {name} could not be read: {error}")
        sys.exit(1)


def load_organizations():
    data = load_json(ORGANIZATION_FILE, "organizations.json")
    organizations = data.get("organizations", {})
    if not organizations:
        print("ERROR: No organizations found in organizations.json.")
        sys.exit(1)
    print(f"Loaded {len(organizations)} organizations.")
    return organizations


def load_state():
    if not STATE_FILE.exists():
        return {"events": {}, "correlations": {}}
    data = load_json(STATE_FILE, "correlation-state.json")
    data.setdefault("events", {})
    data.setdefault("correlations", {})
    print(
        f"Loaded {len(data['events'])} event(s) and "
        f"{len(data['correlations'])} correlation(s) from correlation-state.json."
    )
    return data


def save_state(state):
    temporary = STATE_FILE.with_suffix(".json.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(STATE_FILE)
    print(
        f"Saved {len(state['events'])} event(s) and "
        f"{len(state['correlations'])} correlation(s) to correlation-state.json."
    )


def alias_matches(text, alias):
    alias = str(alias).strip()
    if not alias:
        return False
    return bool(re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", text, re.I))


def searchable_text(event):
    fields = [
        event.get("description", ""), event.get("scope", ""),
        event.get("locations", ""), event.get("asns", ""),
        event.get("event_type", ""), event.get("outage_type", ""),
        event.get("cause", ""), " ".join(event.get("infrastructure", [])),
    ]
    return " ".join(str(value) for value in fields if value).lower()


def identify_organizations(event, catalog):
    text = searchable_text(event)
    matches = []
    for organization_id, organization in catalog.items():
        matched_aliases = [
            alias for alias in organization.get("aliases", [])
            if alias_matches(text, alias)
        ]
        if matched_aliases:
            matches.append({
                "id": organization_id,
                "display_name": organization.get("display_name", organization_id),
                "sector": organization.get("sector", "unknown"),
                "criticality": int(organization.get("criticality", 0)),
                "matched_aliases": matched_aliases,
            })
    return matches


def enrich_event(event, catalog):
    matches = identify_organizations(event, catalog)
    event["organizations"] = matches
    event["organization_ids"] = sorted({item["id"] for item in matches})
    event["organization_names"] = sorted({item["display_name"] for item in matches})
    event["sectors"] = sorted({item["sector"] for item in matches})
    return event


def create_event(event_id, source, description, started, **kwargs):
    infrastructure = kwargs.get("infrastructure", []) or []
    return {
        "event_id": event_id,
        "source": source,
        "description": description,
        "started": format_datetime(started),
        "ended": kwargs.get("ended"),
        "status": kwargs.get("status", "ONGOING"),
        "locations": kwargs.get("locations", "Unknown"),
        "asns": kwargs.get("asns", "Unknown"),
        "scope": kwargs.get("scope", "Unknown"),
        "event_type": kwargs.get("event_type", "OUTAGE"),
        "outage_type": kwargs.get("outage_type", "Unknown"),
        "cause": kwargs.get("cause", "Unknown"),
        "source_url": kwargs.get("source_url", ""),
        "official_acknowledgment": bool(kwargs.get("official_acknowledgment", False)),
        "infrastructure": infrastructure,
        "organizations": [], "organization_ids": [],
        "organization_names": [], "sectors": [],
    }


def fetch_cloudflare():
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        print("ERROR: CLOUDFLARE_API_TOKEN is missing.")
        sys.exit(1)
    response = requests.get(
        CLOUDFLARE_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "global-infrastructure-monitor/4.0",
        },
        params={"dateRange": "1d", "limit": 50, "format": "json"},
        timeout=30,
    )
    print("Cloudflare HTTP status:", response.status_code)
    response.raise_for_status()
    payload = response.json()
    if payload.get("success") is False:
        raise RuntimeError(payload.get("errors"))
    return payload.get("result", {}).get("annotations", [])


def normalize_cloudflare(raw_event, sequence):
    outage = raw_event.get("outage") or {}
    locations = raw_event.get("locations") or []
    asns = raw_event.get("asns") or []
    location_text = ", ".join(map(str, locations)) if isinstance(locations, list) else str(locations)
    asn_text = ", ".join(map(str, asns)) if isinstance(asns, list) else str(asns)
    ended = raw_event.get("endDate")
    stable_source_id = raw_event.get("id") or hashlib.sha256(
        "|".join([
            str(raw_event.get("startDate", "")),
            str(raw_event.get("eventType", "")),
            str(raw_event.get("description", "")),
        ]).encode("utf-8")
    ).hexdigest()[:20]
    return create_event(
        event_id=f"cloudflare-{stable_source_id}",
        source="cloudflare_radar",
        description=raw_event.get("description") or "No description provided",
        started=raw_event.get("startDate"),
        ended=ended,
        status="RESOLVED" if ended else "ONGOING",
        locations=location_text or "Unknown",
        asns=asn_text or "Unknown",
        scope=raw_event.get("scope") or "Unknown",
        event_type=raw_event.get("eventType") or "OUTAGE",
        outage_type=outage.get("outageType") or "Unknown",
        cause=outage.get("outageCause") or "Unknown",
        source_url=raw_event.get("linkedUrl") or "",
    )


def unique_values(events, field):
    return sorted({value for event in events for value in event.get(field, [])})


def distinct_sources(events):
    return sorted({event["source"] for event in events})


def event_span(events):
    values = [parse_datetime(event["started"]) for event in events]
    values = [value for value in values if value]
    return 0 if len(values) < 2 else (max(values) - min(values)).total_seconds() / 60


def shared_infrastructure(events):
    counts = Counter()
    for event in events:
        for value in set(item.lower() for item in event.get("infrastructure", [])):
            counts[value] += 1
    return sorted(value for value, count in counts.items() if count >= 2)


def candidate_windows(events, window_minutes):
    ordered = sorted(
        events,
        key=lambda event: parse_datetime(event["started"])
        or datetime.min.replace(tzinfo=timezone.utc),
    )
    windows = []
    for index, anchor in enumerate(ordered):
        group = []
        for candidate in ordered[index:]:
            difference = minutes_between(anchor["started"], candidate["started"])
            if difference is not None and difference <= window_minutes:
                group.append(candidate)
        windows.append(group)
    return windows


def build_groups(events):
    useful = [event for event in events if event["organization_ids"]]
    groups = []

    for sector in sorted({sector for event in useful for sector in event["sectors"]}):
        sector_events = [event for event in useful if sector in event["sectors"]]
        for candidates in candidate_windows(sector_events, SAME_SECTOR_WINDOW_MINUTES):
            if len(unique_values(candidates, "organization_ids")) >= 2:
                groups.append({"type": "SAME_SECTOR", "sector": sector, "events": candidates})

    for candidates in candidate_windows(useful, CROSS_SECTOR_WINDOW_MINUTES):
        if (
            len(unique_values(candidates, "organization_ids")) >= 3
            and len(unique_values(candidates, "sectors")) >= 2
        ):
            groups.append({"type": "CROSS_SECTOR", "sector": None, "events": candidates})

    # Remove exact duplicates and groups wholly contained in larger groups of the same type/sector.
    unique = []
    seen = set()
    groups.sort(key=lambda item: len(item["events"]), reverse=True)
    for group in groups:
        ids = frozenset(event["event_id"] for event in group["events"])
        signature = (group["type"], group.get("sector"), tuple(sorted(ids)))
        if signature in seen:
            continue
        if any(
            group["type"] == prior["type"]
            and group.get("sector") == prior.get("sector")
            and ids <= frozenset(event["event_id"] for event in prior["events"])
            for prior in unique
        ):
            continue
        seen.add(signature)
        unique.append(group)
    return unique


def score_correlation(group):
    events = group["events"]
    organizations = unique_values(events, "organization_ids")
    sectors = unique_values(events, "sectors")
    sources = distinct_sources(events)
    infrastructure = shared_infrastructure(events)
    score, reasons = 0, []

    if len(organizations) >= 10:
        score += 60; reasons.append("10+ organizations +60")
    elif len(organizations) >= 5:
        score += 45; reasons.append("5-9 organizations +45")
    elif len(organizations) >= 3:
        score += 30; reasons.append("3-4 organizations +30")
    elif len(organizations) == 2:
        score += 15; reasons.append("2 organizations +15")

    sector_counts = Counter()
    for event in events:
        for organization in event["organizations"]:
            sector_counts[organization["sector"]] += 1
    highest = max(sector_counts.values(), default=0)
    if highest >= 3:
        score += 20; reasons.append("3+ organizations in one sector +20")
    elif highest == 2:
        score += 10; reasons.append("2 organizations in one sector +10")

    if len(sectors) >= 4:
        score += 35; reasons.append("4+ sectors +35")
    elif len(sectors) == 3:
        score += 25; reasons.append("3 sectors +25")
    elif len(sectors) == 2:
        score += 15; reasons.append("2 sectors +15")

    if infrastructure:
        score += 20; reasons.append("Shared infrastructure +20")

    combined = " ".join(searchable_text(event) for event in events)
    if any(term in combined for term in ["global", "nationwide", "national", "multiple countries"]):
        score += 15; reasons.append("National/global scope +15")

    if len(sources) >= 3:
        score += 20; reasons.append("3+ independent sources +20")
    elif len(sources) == 2:
        score += 10; reasons.append("2 independent sources +10")
    else:
        score -= 15; reasons.append("Single-source evidence -15")

    return max(0, min(score, 100)), reasons


def score_confidence(group):
    events = group["events"]
    sources = distinct_sources(events)
    infrastructure = shared_infrastructure(events)
    score, reasons = 30, ["At least one structured source +30"]
    if len(sources) >= 2:
        score += 30; reasons.append("Second independent source +30")
    if len(sources) >= 3:
        score += 20; reasons.append("Third independent source +20")
    if any(event.get("official_acknowledgment") for event in events):
        score += 20; reasons.append("Official acknowledgment +20")
    if infrastructure:
        score += 15; reasons.append("Shared infrastructure +15")
    allowed = SAME_SECTOR_WINDOW_MINUTES if group["type"] == "SAME_SECTOR" else CROSS_SECTOR_WINDOW_MINUTES
    if event_span(events) <= allowed:
        score += 10; reasons.append("Matching time window +10")
    return min(score, 100), reasons


def severity(score):
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def confidence(score):
    if score >= 90:
        return "CONFIRMED"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MODERATE"
    return "LOW"


def correlation_id(group):
    events = group["events"]
    earliest = min(
        parse_datetime(event["started"])
        for event in events
        if parse_datetime(event["started"])
    )
    bucket = earliest.replace(
        minute=(earliest.minute // 30) * 30,
        second=0,
        microsecond=0,
    ).isoformat()
    # Keep organization and cross-sector membership out of the family ID.
    # That allows added organizations or sectors to be classified as expansion.
    family_scope = group.get("sector") or "multi-sector"
    raw = "|".join([group["type"], family_scope, bucket])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def determine_action(current, previous):
    if previous is None:
        return "NEW_CORRELATION"
    current_orgs = set(current["organization_ids"])
    previous_orgs = set(previous.get("organization_ids", []))
    if current["status"] == "RESOLVED" and previous.get("status") == "ONGOING":
        return "RESOLVED_CORRELATION"
    if severity(current["score"]) != previous.get("severity") and current["score"] > int(previous.get("score", 0)):
        return "ESCALATED_CORRELATION"
    if current_orgs > previous_orgs:
        return "EXPANDED_CORRELATION"
    if (
        current_orgs == previous_orgs
        and current["score"] == int(previous.get("score", 0))
        and current["confidence_score"] == int(previous.get("confidence_score", 0))
    ):
        return "DUPLICATE_CORRELATION"
    return "UPDATED_CORRELATION"


def build_record(group):
    score, score_reasons = score_correlation(group)
    confidence_score, confidence_reasons = score_confidence(group)
    events = group["events"]
    return {
        "type": group["type"],
        "sector": group.get("sector"),
        "status": "ONGOING" if any(event["status"] == "ONGOING" for event in events) else "RESOLVED",
        "score": score,
        "severity": severity(score),
        "confidence_score": confidence_score,
        "confidence": confidence(confidence_score),
        "organization_ids": unique_values(events, "organization_ids"),
        "organization_names": unique_values(events, "organization_names"),
        "sectors": unique_values(events, "sectors"),
        "sources": distinct_sources(events),
        "shared_infrastructure": shared_infrastructure(events),
        "event_ids": sorted(event["event_id"] for event in events),
        "time_span_minutes": round(event_span(events), 1),
        "score_reasons": score_reasons,
        "confidence_reasons": confidence_reasons,
    }


def should_would_email(action, record):
    if action in {"DUPLICATE_CORRELATION", "UPDATED_CORRELATION"}:
        return False
    if action == "RESOLVED_CORRELATION":
        return True
    return record["score"] >= HIGH_THRESHOLD and record["confidence_score"] >= MINIMUM_EMAIL_CONFIDENCE


def store_event(state, event):
    existing = state["events"].get(event["event_id"], {})
    state["events"][event["event_id"]] = {
        "first_seen": existing.get("first_seen") or now_utc(),
        "last_seen": now_utc(),
        "source": event["source"],
        "started": event["started"],
        "ended": event["ended"],
        "status": event["status"],
        "organization_ids": event["organization_ids"],
        "sectors": event["sectors"],
        "description": event["description"],
    }


def store_correlation(state, correlation_key, record, action):
    previous = state["correlations"].get(correlation_key, {})
    state["correlations"][correlation_key] = {
        **record,
        "first_seen": previous.get("first_seen") or now_utc(),
        "last_seen": now_utc(),
        "last_action": action,
        "last_alerted": previous.get("last_alerted"),
        "alert_count": int(previous.get("alert_count", 0)),
    }


def display_correlation(number, correlation_key, record, action):
    print("\n" + "=" * 75)
    print(f"Correlation #{number}")
    print("=" * 75)
    print(f"Correlation ID:   {correlation_key}")
    print(f"Action:           {action}")
    print(f"Type:             {record['type']}")
    print(f"Severity:         {record['severity']} ({record['score']}/100)")
    print(f"Confidence:       {record['confidence']} ({record['confidence_score']}/100)")
    print(f"Time span:        {record['time_span_minutes']} minutes")
    print("Organizations:")
    for name in record["organization_names"]:
        print(f"  - {name}")
    print("Sectors:")
    for value in record["sectors"]:
        print(f"  - {value}")
    print("Sources:")
    for value in record["sources"]:
        print(f"  - {value}")
    if should_would_email(action, record):
        print(">>> WOULD SEND CORRELATION EMAIL <<<")
    else:
        print("No correlation email would be sent.")


def synthetic_events(catalog):
    raw = [
        create_event("syn-bank-1", "source_a", "JPMorgan Chase online banking is experiencing problems.", "2026-11-17T18:00:00Z", official_acknowledgment=True),
        create_event("syn-bank-2", "source_b", "Bank of America customers report online banking failures.", "2026-11-17T18:18:00Z"),
        create_event("syn-bank-3", "source_c", "Wells Fargo digital banking services are unavailable.", "2026-11-17T18:31:00Z"),
        create_event("syn-cross-1", "source_ms", "Microsoft 365 and Outlook are experiencing a global outage.", "2026-11-17T20:00:00Z", scope="Global", infrastructure=["akamai"], official_acknowledgment=True),
        create_event("syn-cross-2", "source_pay", "Mastercard payment processing is experiencing widespread failures.", "2026-11-17T20:17:00Z", infrastructure=["akamai"]),
        create_event("syn-cross-3", "source_gov", "Federal Aviation Administration online services are unavailable.", "2026-11-17T20:36:00Z", infrastructure=["akamai"]),
    ]
    return [enrich_event(event, catalog) for event in raw]


def process_dataset(label, events, state):
    print(f"\n--- {label} ---")
    for event in events:
        store_event(state, event)
    groups = build_groups(events)
    actions = Counter()
    for number, group in enumerate(groups, 1):
        key = correlation_id(group)
        record = build_record(group)
        previous = state["correlations"].get(key)
        action = determine_action(record, previous)
        actions[action] += 1
        display_correlation(number, key, record, action)
        store_correlation(state, key, record, action)
    print(f"{label} correlation groups: {len(groups)}")
    for action, count in sorted(actions.items()):
        print(f"  {action}: {count}")
    return groups


def main():
    print("=" * 75)
    print(" GLOBAL INFRASTRUCTURE MONITOR")
    print(" PERSISTENT CORRELATION DRY RUN")
    print("=" * 75)
    print("EMAIL DELIVERY: DISABLED")
    print("PRODUCTION state.json: UNTOUCHED")

    catalog = load_organizations()
    state = load_state()

    # Synthetic correlations make persistence testable on every run.
    synthetic = synthetic_events(catalog)
    process_dataset("SYNTHETIC", synthetic, state)

    print("\nConnecting to Cloudflare Radar...")
    try:
        raw_events = fetch_cloudflare()
    except (requests.RequestException, RuntimeError, ValueError) as error:
        print(f"ERROR retrieving Cloudflare data: {error}")
        sys.exit(1)

    live = [
        enrich_event(normalize_cloudflare(raw, index), catalog)
        for index, raw in enumerate(raw_events, 1)
    ]
    print(f"Cloudflare returned {len(live)} event(s).")
    process_dataset("LIVE", live, state)

    save_state(state)
    print("\nPersistent correlation dry run completed successfully.")
    print("No emails were sent.")


if __name__ == "__main__":
    main()

