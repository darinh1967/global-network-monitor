import os
import requests

print("===================================")
print(" Global Network Monitor")
print("===================================")
print()

token = os.environ["CLOUDFLARE_API_TOKEN"].strip()

url = "https://api.cloudflare.com/client/v4/radar/annotations/outages"

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/json"
}

params = {
    "dateRange": "1d",
    "limit": 20,
    "format": "json"
}

print("Connecting to Cloudflare Radar...")
print()

try:

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=30
    )

    print("Cloudflare HTTP status:", response.status_code)

    response.raise_for_status()

    data = response.json()

    if not data.get("success", False):
        print("Cloudflare returned an API error.")
        print(data.get("errors"))
        raise SystemExit(1)

    result = data.get("result", {})

    outages = result.get("annotations", [])

    print()
    print(f"Outages returned: {len(outages)}")
    print()

    if not outages:

        print("No outage events were returned.")

    else:

        print("Recent Internet outage events:")
        print()

        for number, event in enumerate(outages, start=1):

            outage = event.get("outage") or {}

            print("-----------------------------------")
            print(f"Event #{number}")
            print("-----------------------------------")

            print(
                "Started:",
                event.get("startDate", "Unknown")
            )

            print(
                "Ended:",
                event.get("endDate") or "ONGOING"
            )

            print(
                "Location:",
                event.get("locations", "Unknown")
            )

            print(
                "ASN:",
                event.get("asns", "Unknown")
            )

            print(
                "Scope:",
                event.get("scope", "Unknown")
            )

            print(
                "Type:",
                outage.get("outageType", "Unknown")
            )

            print(
                "Cause:",
                outage.get("outageCause", "Unknown")
            )

            print()

except requests.exceptions.HTTPError as error:

    print()
    print("Cloudflare rejected the request.")
    print(error)

    if response.status_code == 401:
        print()
        print("Likely problem: API token authentication.")

    if response.status_code == 403:
        print()
        print("Likely problem: API token permissions.")

    raise SystemExit(1)

except requests.exceptions.RequestException as error:

    print()
    print("Unable to connect to Cloudflare Radar.")
    print(error)

    raise SystemExit(1)


print()
print("Cloudflare Radar test completed successfully.")
