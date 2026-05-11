# Zscaler Certificate Management

**Author:** Nathan Bray

Scripts to audit and install Zscaler root certificate trust on Linux/Unix and Windows systems. Many development tools (Python, Node.js, Git, Azure CLI, Java) maintain their own certificate stores and do not automatically trust certificates installed at the OS level. These scripts detect gaps and fix them.

---

## Scripts

| Script | Platform | Shell |
|--------|----------|-------|
| `install-zscaler-trust.sh` | Linux/Unix (RHEL, CentOS, Fedora, Debian, Ubuntu) | Bash |
| `Install-ZscalerTrust.ps1` | Windows | PowerShell 5.0+ |

Both scripts provide the same core workflow: **Audit** the current state of certificate trust, **Install** certificates and configure tools, or **Rollback** all changes.

---

## Modes of Operation

| Mode | Description |
|------|-------------|
| **Default** (no flags) | Runs an audit then presents an interactive menu |
| **Audit** | Read-only scan of certificate trust status across all detected tools |
| **Install** | Non-interactive installation of certificates and environment configuration |
| **Rollback** | Removes all certificates, environment variables, and patches applied by the script |

---

## Linux/Unix Usage

```bash
# Interactive mode (audit + menu)
./install-zscaler-trust.sh

# Audit only
./install-zscaler-trust.sh --audit

# Audit with a live TLS handshake test
./install-zscaler-trust.sh --audit --test-connection

# Non-interactive install from a local PEM file
./install-zscaler-trust.sh --install --cert-file /path/to/zscaler.pem

# Install by fetching certificates from a URL
./install-zscaler-trust.sh --install --cert-url https://it.corp.example.com/root.cer

# Install from multiple sources
./install-zscaler-trust.sh --install \
  --cert-url https://it.corp.example.com/root.cer \
  --cert-url https://proxy.corp.example.com

# Install with Azure CLI and Git patching
./install-zscaler-trust.sh --install --patch-azure-cli --patch-git

# System-wide installation (requires root)
sudo ./install-zscaler-trust.sh --install --scope system

# Rollback all changes
./install-zscaler-trust.sh --rollback

# Force rollback without confirmation prompt
./install-zscaler-trust.sh --rollback --force
```

### Linux/Unix Options

```
Modes (mutually exclusive):
  --audit                   Audit only, no changes made
  --install                 Non-interactive install
  --rollback                Undo all script-managed changes
  (no flag)                 Audit + interactive menu

Options:
  --cert-file FILE          PEM file containing Zscaler certificate(s)
  --cert-url URL            Fetch certs from URL (repeatable)
  --cert-url-timeout N      Timeout per URL in seconds (default: 10)
  --bundle-dir DIR          Output directory for PEM files (default: ~/certs)
  --test-connection         Include TLS handshake test in audit
  --test-host HOST          TLS test target (default: login.microsoftonline.com)
  --patch-azure-cli         Patch Azure CLI certifi bundle
  --patch-git               Configure git http.sslCAInfo
  --force                   Skip confirmation with --rollback
  --scope user|system       Env var scope (default: user; system needs root)
  --shell bash|zsh|both     Target shell profile (default: auto-detect)
  -h, --help                Show help
```

---

## Windows Usage

```powershell
# Interactive mode (audit + menu)
.\Install-ZscalerTrust.ps1

# Audit only
.\Install-ZscalerTrust.ps1 -Audit

# Audit with a live TLS handshake test
.\Install-ZscalerTrust.ps1 -Audit -TestConnection

# Non-interactive install
.\Install-ZscalerTrust.ps1 -Install

# Install with Azure CLI patching (may require admin)
.\Install-ZscalerTrust.ps1 -Install -PatchAzureCli

# Machine-wide install (requires admin)
.\Install-ZscalerTrust.ps1 -Install -Scope Machine

# Fetch certificates from one or more URLs
.\Install-ZscalerTrust.ps1 -Install -CertUrls @(
    'https://it.corp.example.com/root.cer',
    'https://internal-app.corp.example.com'
)

# Rollback all changes
.\Install-ZscalerTrust.ps1 -Rollback

# Force rollback without confirmation
.\Install-ZscalerTrust.ps1 -Rollback -Force
```

### Windows Parameters

```
Modes (mutually exclusive):
  -Audit                  Audit only, no changes made
  -Install                Non-interactive install
  -Rollback               Undo all script-managed changes
  (no flag)               Audit + interactive menu

Options:
  -TestConnection         Include TLS handshake test in audit
  -TestHost <hostname>    TLS test target (default: login.microsoftonline.com)
  -BundleDir <path>       Output directory for PEM files (default: $env:USERPROFILE\certs)
  -PatchAzureCli          Patch Azure CLI certifi bundle
  -Scope User|Machine     Env var scope (default: User; Machine needs admin)
  -CertUrls <string[]>    URLs to fetch certificates from
  -CertUrlTimeoutSec <n>  Per-URL timeout in seconds (default: 10)
  -Force                  Skip confirmation with -Rollback
```

---

## What Gets Configured

### Environment Variables

The scripts set the following environment variables so that common tools trust the Zscaler certificate:

| Variable | Used By |
|----------|---------|
| `REQUESTS_CA_BUNDLE` | Python `requests` library |
| `SSL_CERT_FILE` | OpenSSL-based tools |
| `CURL_CA_BUNDLE` | curl |
| `NODE_EXTRA_CA_CERTS` | Node.js |
| `PIP_CERT` | pip |

### Generated Files

| File | Description |
|------|-------------|
| `~/certs/zscaler-certs.pem` | Extracted Zscaler root certificate(s) |
| `~/certs/combined-ca-bundle.pem` | System CA bundle combined with Zscaler certs |

### Tool-Specific Patches

| Tool | What Changes |
|------|-------------|
| Azure CLI | Appends Zscaler cert to the bundled `certifi` CA file |
| Git | Sets `http.sslCAInfo` to the combined bundle |
| npm | Sets `cafile` configuration to the combined bundle |
| Java | Imports the cert into the JVM keystore via `keytool` |

---

## Certificate Sources

The scripts can discover Zscaler certificates from multiple sources:

- **Windows Certificate Store** (PowerShell) -- `LocalMachine\Root`, `LocalMachine\CA`, `CurrentUser\Root`, etc.
- **Local PEM file** -- via `--cert-file` / direct input
- **HTTP download** -- `.cer`, `.crt`, `.pem`, `.der` files from a URL
- **TLS handshake capture** -- connects to a host and extracts the presented certificate chain
- **System trust store** (Linux) -- scans `/etc/pki/ca-trust` or `/usr/share/ca-certificates`

---

## Requirements

### Linux/Unix
- Bash shell
- `openssl`, `awk`, `sed`, `grep`, `mktemp`
- `curl` or `wget` (only needed for `--cert-url`)
- Root access (only needed for `--scope system`)

### Windows
- PowerShell 5.0+
- Administrator privileges (only needed for `-Scope Machine` or `-PatchAzureCli`)
