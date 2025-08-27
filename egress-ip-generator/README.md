# Zscaler Egress IP Extractor

**Author:** Nathan Bray  
**Version:** 1.1  

---

## 📌 Overview

This Python script fetches all publicly available **Zscaler egress IP addresses** from Zscaler's published JSON endpoint and outputs them into a `.json` file.  

It supports:

- Pulling from Zscaler's official URL (default)
- Overriding the URL with a custom endpoint (for lab/mirrored environments)
- Specifying a custom output filename
- Generating **detailed metadata per IP** (default)
- Generating **summarized CIDR blocks** of ready IPs (`--summarize`)

---

## 🚀 Features

- Pulls egress IPs from Zscaler's real-time published API
- Filters out entries not ready for use (based on metadata flags)
- Supports multi-VIP and standard entries
- `--summarize` mode collapses IPv4 and IPv6 IPs into minimal CIDR blocks
- Flexible CLI flags for URL, output filename, and summarization
- Clean JSON output

---

## 🛠️ Requirements

- Python 3.10+
- `requests` library (install with `pip install requests`)

---

## 📥 Installation

Clone the repo or download the script:

```bash
git clone https://github.com/mancow2001/Zscaler-Tools.git
cd egress-ip-generator
---

