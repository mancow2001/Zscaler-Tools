# Zscaler Tools

**Author:** Nathan Bray

A collection of utilities for managing Zscaler Zero Trust Network Access deployments. This toolkit helps IT and security teams handle certificate trust configuration and egress IP address management across Linux, Windows, and macOS environments.

---

## Modules

### [cert-management/](cert-management/)

Scripts to audit, install, and manage Zscaler root certificate trust for development tools and CLI applications that do not honor the system trust store. Provides platform-specific scripts for Linux/Unix (Bash), macOS (Bash), and Windows (PowerShell) with feature parity. Coverage tracks the Zscaler help guide *Adding Custom Certificate to an Application-Specific Trust Store*.

**Supported tools:** Python (`requests`, pip, `pip-system-certs`, `pip config global.cert`), Node.js (npm `cafile`, `NODE_EXTRA_CA_CERTS`), Java (keytool), Git, curl (env var + rc file), Wget (rc file), Azure CLI, AWS CLI / Boto, Google Cloud SDK, Composer / PHP, plus OS-level trust stores (Keychain / `LocalMachine\Root` / `update-ca-trust` / `update-ca-certificates`). Ruby, Databricks Connect, Rust, and Fastlane inherit trust from the env vars and OS trust store the scripts manage.

### [egress-ip-generator/](egress-ip-generator/)

Python tool to fetch Zscaler's publicly available egress IP addresses from their configuration API and export them as JSON. Useful for building firewall allow-lists, proxy configurations, and network security policies.

---

## Quick Start

### Certificate Management

```bash
# Linux - audit current certificate trust status
./cert-management/install-zscaler-trust.sh --audit

# macOS - audit current certificate trust status
./cert-management/install-zscaler-trust-macos.sh --audit

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
| cert-management (macOS) | macOS 10.15+, Bash, openssl, security CLI; sudo for System keychain |
| cert-management (Windows) | PowerShell 5.0+; admin privileges for machine-wide ops |
| egress-ip-generator | Python 3.10+, `requests` library                      |

---

## License

See individual module directories for details.
