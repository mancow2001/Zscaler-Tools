# Zscaler Tools

**Author:** Nathan Bray

A collection of utilities for managing Zscaler Zero Trust Network Access deployments. This toolkit helps IT and security teams handle certificate trust configuration and egress IP address management across Linux, Windows, and macOS environments.

---

## Modules

### [cert-management/](cert-management/)

Scripts to audit, install, and manage Zscaler root certificate trust for development tools and CLI applications that do not honor the system trust store. Provides platform-specific scripts for both Linux/Unix (Bash) and Windows (PowerShell) with feature parity.

**Supported tools:** Python, Node.js, Git, npm, Azure CLI, Java, curl, pip

### [egress-ip-generator/](egress-ip-generator/)

Python tool to fetch Zscaler's publicly available egress IP addresses from their configuration API and export them as JSON. Useful for building firewall allow-lists, proxy configurations, and network security policies.

---

## Quick Start

### Certificate Management

```bash
# Linux/macOS - audit current certificate trust status
./cert-management/install-zscaler-trust.sh --audit

# Windows - audit current certificate trust status
.\cert-management\Install-ZscalerTrust.ps1 -Audit
```

### Egress IP Generator

```bash
cd egress-ip-generator
pip install requests
python3 zscaler_egress_ips.py
```

---

## Requirements

| Module              | Requirements                                           |
|---------------------|--------------------------------------------------------|
| cert-management (Linux) | Bash, openssl, awk, sed, grep; curl/wget for URL fetch |
| cert-management (Windows) | PowerShell 5.0+; admin privileges for machine-wide ops |
| egress-ip-generator | Python 3.10+, `requests` library                      |

---

## License

See individual module directories for details.
