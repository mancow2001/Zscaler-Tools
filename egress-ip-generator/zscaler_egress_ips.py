#!/usr/bin/env python3
"""
zscaler_egress_ips.py

Author: Nathan Bray

Description:
    This script fetches the current Zscaler egress IP addresses from the
    publicly available Zscaler configuration API endpoint and saves the result
    into a structured JSON file.

    - By default: outputs detailed IP info with metadata.
    - With --summarize: outputs consolidated CIDR blocks in simplified JSON.

Usage:
    python3 zscaler_egress_ips.py
    python3 zscaler_egress_ips.py --summarize
    python3 zscaler_egress_ips.py --url <custom_url> --output <filename>
"""

import requests
import json
import argparse
import ipaddress

# Default Zscaler public egress IP endpoint
DEFAULT_URL = "https://config.zscaler.com/api/getdata/zscaler.net/all/cenr?site=config.zscaler.com"

def fetch_zscaler_egress_ips(url=DEFAULT_URL):
    """
    Fetch Zscaler egress IPs from the provided API endpoint.

    Args:
        url (str): The API endpoint to query.

    Returns:
        list: A list of dictionaries representing IP addresses and metadata.

    Example output (default mode):
    [
      {
        "ip_address": "185.46.212.88",
        "region": "North America",
        "location": "Dallas, TX",
        "multivip": true,
        "ready": true
      },
      {
        "ip_address": "147.161.174.0/23",
        "region": "Europe",
        "location": "Frankfurt, DE",
        "multivip": false,
        "ready": true
      }
    ]
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
        cols = region.get("cols", [])
        for col in cols:
            data_items = col.get("data", [])
            for entry in data_items:
                # If entry is a multivip group, loop through each member
                if entry.get("multivip"):
                    for sub in entry.get("data", []):
                        is_ready = not any(note.get("id") == 3 for note in sub.get("notes", []))
                        results.append({
                            "ip_address": sub.get("ip_address"),
                            "region": sub.get("region"),
                            "location": sub.get("location"),
                            "multivip": True,
                            "ready": is_ready
                        })
                else:
                    is_ready = not any(note.get("id") == 3 for note in entry.get("notes", []))
                    results.append({
                        "ip_address": entry.get("ip_address"),
                        "region": entry.get("region"),
                        "location": entry.get("location"),
                        "multivip": False,
                        "ready": is_ready
                    })

    return results

def summarize_ip_blocks(ip_entries):
    """
    Collapse ONLY the IPs marked ready=True into minimal CIDR blocks.
    IPv4 and IPv6 are summarized separately and combined in the output.

    Args:
        ip_entries (list[dict]): Each item should contain:
            - 'ip_address' (str): IP or CIDR
            - 'ready' (bool): only True entries are summarized

    Returns:
        list[dict]: [{"ip_address": "<cidr>"} ...]

    Example output (--summarize mode):
    [
      { "ip_address": "147.161.174.0/23" },
      { "ip_address": "185.46.212.0/24" },
      { "ip_address": "2400:7aa0::/32" }
    ]
    """
    ipv4, ipv6 = [], []

    for item in ip_entries:
        # Only include entries explicitly marked ready=True
        if not item.get("ready", False):
            continue

        raw = item.get("ip_address")
        if not raw:
            continue

        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                ipv4.append(net)
            else:
                ipv6.append(net)
        except ValueError as ve:
            print(f"[WARN] Skipping invalid IP '{raw}': {ve}")

    # Collapse separately to avoid mixed-version errors
    collapsed_v4 = list(ipaddress.collapse_addresses(ipv4))
    collapsed_v6 = list(ipaddress.collapse_addresses(ipv6))

    # Merge results and format as required
    collapsed = collapsed_v4 + collapsed_v6
    return [{"ip_address": str(cidr)} for cidr in collapsed]
    
def save_as_json(data, filename="zscaler_egress_ips.json"):
    """
    Save the extracted IP data into a JSON file.

    Args:
        data (list): List of IPs or IP blocks.
        filename (str): Path to output JSON file.
    """
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] Saved {len(data)} entries to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch Zscaler egress IPs and save to JSON.")
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
    parser.add_argument(
        "--summarize",
        help="Output summarized CIDR blocks instead of full metadata",
        action="store_true"
    )
    args = parser.parse_args()

    try:
        full_ips = fetch_zscaler_egress_ips(url=args.url)
        if args.summarize:
            summarized = summarize_ip_blocks(full_ips)
            save_as_json(summarized, filename=args.output)
        else:
            save_as_json(full_ips, filename=args.output)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch data: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
