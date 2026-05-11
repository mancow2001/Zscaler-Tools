# Zscaler Egress IP Extractor

**Author:** Nathan Bray
**Version:** 1.1

---

## Overview

This Python script fetches all publicly available Zscaler egress IP addresses from Zscaler's published JSON endpoint and exports them to a `.json` file. The output can be used for firewall allow-lists, proxy configurations, and network security policies.

It supports:

- Pulling from Zscaler's official API (default)
- Overriding the URL with a custom endpoint (for lab or mirrored environments)
- Specifying a custom output filename
- Generating detailed metadata per IP (default mode)
- Generating summarized CIDR blocks of ready IPs (`--summarize` mode)

---

## Requirements

- Python 3.10+
- `requests` library

```bash
pip install requests
```

---

## Usage

```bash
# Default -- fetch all IPs with full metadata
python3 zscaler_egress_ips.py

# Summarize into minimal CIDR blocks (ready IPs only)
python3 zscaler_egress_ips.py --summarize

# Custom output filename
python3 zscaler_egress_ips.py --output my_ips.json

# Custom API endpoint
python3 zscaler_egress_ips.py --url https://custom.endpoint/api

# Combine options
python3 zscaler_egress_ips.py --summarize --output summarized.json
```

### Options

```
--url <URL>          Override the default Zscaler API endpoint
--output <filename>  Output JSON filename (default: zscaler_egress_ips.json)
--summarize          Output consolidated CIDR blocks instead of full metadata
```

---

## Output Formats

### Default (full metadata)

Each entry includes the IP address or CIDR block along with location and status metadata:

```json
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
```

### Summarized (`--summarize`)

Filters to ready IPs only, then collapses overlapping ranges into minimal CIDR notation. IPv4 and IPv6 are handled separately:

```json
[
  { "ip_address": "147.161.174.0/23" },
  { "ip_address": "185.46.212.0/24" },
  { "ip_address": "2400:7aa0::/32" }
]
```

---

## How It Works

1. Fetches IP data from the Zscaler configuration API
2. Parses the nested JSON response to extract individual IP entries
3. Collects metadata: IP address, region, location, multi-VIP status, and readiness
4. In `--summarize` mode, filters to ready entries and collapses them into minimal CIDR blocks using Python's `ipaddress` module
5. Writes the result to a JSON file
