#!/usr/bin/env python3
"""
zscaler_egress_ips.py

Author: Nathan Bray

Description:
    This script fetches the current Zscaler egress IP addresses from the
    publicly available Zscaler configuration API endpoint and saves the result
    into a structured JSON file. It can also accept a custom URL for alternate
    endpoints and allows the output filename to be specified.

Usage:
    python3 zscaler_egress_ips.py
    python3 zscaler_egress_ips.py --url <custom_url>
    python3 zscaler_egress_ips.py --output <filename>
"""

import requests
import json
import argparse

# Default Zscaler public egress IP endpoint
DEFAULT_URL = "https://config.zscaler.com/api/getdata/zscaler.net/all/cenr?site=config.zscaler.com"

def fetch_zscaler_egress_ips(url=DEFAULT_URL):
    """
    Fetch Zscaler egress IPs from the provided API endpoint.

    Args:
        url (str): The API endpoint to query.

    Returns:
        list: A list of dictionaries representing IP addresses and metadata.
    """
    print(f"[INFO] Fetching from: {url}")
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()

    # The IP data is stored in this deeply nested structure
    entries = data.get("data", [])[6]["body"]["json"]["rows"][1:]
    results = []

    # Iterate through all region entries and extract usable IPs
    for region in entries:
        region_name = region.get("region")
        cols = region.get("cols", [])
        for col in cols:
            data_items = col.get("data", [])
            for entry in data_items:
                # If entry is a multivip group, loop through each member
                if entry.get("multivip"):
                    for sub in entry.get("data", []):
                        # Skip entries marked as not ready (note id 3)
                        if not any(note.get("id") == 3 for note in sub.get("notes", [])):
                            results.append({
                                "ip_address": sub.get("ip_address"),
                                "region": sub.get("region"),
                                "location": sub.get("location"),
                                "multivip": True
                            })
                else:
                    # Single IP entries
                    if not any(note.get("id") == 3 for note in entry.get("notes", [])):
                        results.append({
                            "ip_address": entry.get("ip_address"),
                            "region": entry.get("region"),
                            "location": entry.get("location"),
                            "multivip": False
                        })

    return results

def save_as_json(data, filename="zscaler_egress_ips.json"):
    """
    Save the extracted IP data into a JSON file.

    Args:
        data (list): List of dictionaries containing IP info.
        filename (str): Path to output JSON file.
    """
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] Saved {len(data)} entries to {filename}")

if __name__ == "__main__":
    # Command-line interface
    parser = argparse.ArgumentParser(
        description="Fetch Zscaler egress IPs and save them into a JSON file."
    )
    parser.add_argument(
        "--url",
        help=f"Override the default Zscaler JSON URL (default: {DEFAULT_URL})",
        default=DEFAULT_URL
    )
    parser.add_argument(
        "--output",
        help="Output JSON filename (default: zscaler_egress_ips.json)",
        default="zscaler_egress_ips.json"
    )
    args = parser.parse_args()

    # Execute workflow
    try:
        ips = fetch_zscaler_egress_ips(url=args.url)
        save_as_json(ips, filename=args.output)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch data: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
