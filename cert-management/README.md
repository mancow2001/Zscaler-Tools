# Zscaler Certificate Management

**Author:** Nathan Bray

Scripts to audit and install Zscaler root certificate trust on Linux/Unix, macOS, and Windows. Many development tools maintain their own certificate stores and do not automatically trust certificates installed at the OS level; these scripts detect the gaps and fix them.

Coverage tracks the Zscaler help guide *Adding Custom Certificate to an Application-Specific Trust Store*.

---

## Scripts

| Script | Platform | Shell |
|--------|----------|-------|
| `install-zscaler-trust.sh` | Linux/Unix (RHEL, CentOS, Fedora, Debian, Ubuntu, OpenSUSE) | Bash |
| `install-zscaler-trust-macos.sh` | macOS (Apple Silicon and Intel) | Bash |
| `Install-ZscalerTrust.ps1` | Windows | PowerShell 5.0+ |

All three scripts share the same workflow: **Audit** the current trust state, **Install** certificates and configure tools, or **Rollback** every change the script could have applied.

---

## Application coverage

Each row maps to a section in the Zscaler help guide. **Yes** = configured automatically (audit + install + rollback). **Indirect** = covered by env vars the script already sets, no per-tool config written. **N/A** = not applicable on that platform. **No** = intentionally not handled.

| Application | What the script does | Linux | macOS | Windows |
|---|---|:---:|:---:|:---:|
| System trust store | Install root certs to the OS store (sudo / admin) | Yes (`update-ca-trust` / `update-ca-certificates`) | Yes (System + Login keychain) | Yes (`Cert:\LocalMachine\Root` + `CurrentUser\Root`) |
| Python `requests` | `REQUESTS_CA_BUNDLE` env var | Yes | Yes | Yes |
| pip env vars | `PIP_CERT`, `SSL_CERT_FILE` | Yes | Yes | Yes |
| pip config | `pip config set global.cert <bundle>` | Yes (`--patch-pip`) | Yes (`--patch-pip`) | Yes (`-PatchPip`) |
| pip-system-certs | Install package into Azure CLI Python | Yes | Yes | Yes |
| npm | `cafile` + `NODE_EXTRA_CA_CERTS` | Yes (`--patch-npm`) | Yes (`--patch-npm`) | Yes (`-PatchNpm`) |
| Java keytool | Import into JVM `cacerts` | Yes (`--patch-java`) | Yes (`--patch-java`) | Yes (`-PatchJava`) |
| Git | `git config --global http.sslCAInfo` | Yes (`--patch-git`) | Yes (`--patch-git`) | Yes (`-PatchGit`) |
| cURL | `cacert=` block in `~/.curlrc` (or `_curlrc` on Windows) + `CURL_CA_BUNDLE` | Yes (`--patch-curl`) | Yes (`--patch-curl`) | Yes (`-PatchCurl`) |
| GNU Wget | `ca_certificate=` block in `~/.wgetrc` | Yes (`--patch-wget`) | Yes (`--patch-wget`) | Yes (`-PatchWget`) |
| AWS CLI / Boto | `aws configure set default.ca_bundle` | Yes (`--patch-aws`) | Yes (`--patch-aws`) | Yes (`-PatchAws`) |
| Google Cloud SDK | `gcloud config set core/custom_ca_certs_file` | Yes (`--patch-gcloud`) | Yes (`--patch-gcloud`) | Yes (`-PatchGcloud`) |
| Azure CLI | Append cert to bundled `certifi` cacert.pem | Yes (`--patch-azure-cli`) | Yes (`--patch-azure-cli`) | Yes (`-PatchAzureCli`) |
| Composer (PHP) | `openssl.cafile=` block in loaded `php.ini` | Yes (`--patch-composer`) | Yes (`--patch-composer`) | Yes (`-PatchComposer`) |
| Ruby / gem | `SSL_CERT_FILE` env var | Indirect | Indirect | Indirect |
| Databricks Connect | `REQUESTS_CA_BUNDLE` env var | Indirect | Indirect | Indirect |
| Rust (Linux) | OS trust store | Indirect | N/A | N/A |
| Fastlane (Linux) | OS trust store | Indirect | N/A | N/A |
| Snowflake ODBC | not configured — Snowflake uses cert pinning, requires SSL-inspection bypass list (see help guide) | No | No | No |
| Android Studio, IntelliJ, Firefox, Edge, Salesforce Data Loader | not configured — GUI-driven or very narrow audience | No | No | No |

---

## Modes of Operation

| Mode | Description |
|------|-------------|
| **Default** (no flags) | Audit then interactive menu |
| **Audit** | Read-only scan of every supported target |
| **Install** | Non-interactive — runs whichever `--patch-*` flags are set |
| **Rollback** | Detect and undo every script-managed change |

---

## Linux/Unix Usage

```bash
# Interactive mode (audit + menu)
./install-zscaler-trust.sh

# Audit only
./install-zscaler-trust.sh --audit

# Audit with a live TLS handshake test
./install-zscaler-trust.sh --audit --test-connection

# Non-interactive install — bundle + env vars only, no tool patches
./install-zscaler-trust.sh --install --cert-file /path/to/zscaler.pem

# One-shot: do every available patch on every detected tool
sudo ./install-zscaler-trust.sh --install --cert-file zscaler.pem --patch-all

# Cherry-pick patches
./install-zscaler-trust.sh --install --cert-file zscaler.pem \
    --patch-git --patch-npm --patch-aws --patch-gcloud --patch-pip

# Fetch certs from one or more URLs instead of a file
./install-zscaler-trust.sh --install \
    --cert-url https://it.corp.example.com/root.cer \
    --cert-url https://proxy.corp.example.com \
    --patch-all

# System-wide installation (requires root; writes /etc/profile.d/zscaler-trust.sh)
sudo ./install-zscaler-trust.sh --install --scope system --patch-all

# Rollback all changes
./install-zscaler-trust.sh --rollback

# Force rollback without confirmation
./install-zscaler-trust.sh --rollback --force
```

### Linux/Unix Options

```
Modes (mutually exclusive):
  --audit                Audit only, no changes
  --install              Non-interactive install
  --rollback             Undo all script-managed changes
  (no flag)              Audit + interactive menu

Cert sources:
  --cert-file FILE       Local PEM/DER file containing Zscaler cert(s)
  --cert-url URL         Fetch certs from URL (repeatable). HTTP download for
                         .cer/.crt/.pem/.der URLs; TLS handshake otherwise
  --cert-url-timeout N   Per-URL timeout, seconds (default: 10)
  --bundle-dir DIR       Output directory for bundles (default: ~/certs)

Patch flags (only with --install; each is opt-in):
  --patch-azure-cli      Patch Azure CLI's bundled certifi cacert.pem
  --patch-git            git config --global http.sslCAInfo
  --patch-npm            npm config set cafile
  --patch-java           keytool import into JVM cacerts (needs sudo)
  --patch-aws            aws configure set default.ca_bundle
  --patch-gcloud         gcloud config set core/custom_ca_certs_file
  --patch-pip            pip config set global.cert (generic Python)
  --patch-curl           Write cacert= block to ~/.curlrc
  --patch-wget           Write ca_certificate= block to ~/.wgetrc
  --patch-composer       Write openssl.cafile= block to php.ini
  --patch-all            Turn on every --patch-* flag above

Other:
  --test-connection      Live TLS handshake test in audit
  --test-host HOST       TLS test target (default: login.microsoftonline.com)
  --scope user|system    Env var scope (default: user; system needs sudo)
  --shell bash|zsh|both  Target shell profile (default: auto-detect)
  --force                With --rollback: skip the y/N confirmation prompt
  -h, --help             Show help
```

---

## macOS Usage

```bash
# Interactive mode (audit + menu)
./install-zscaler-trust-macos.sh

# Audit only
./install-zscaler-trust-macos.sh --audit

# One-shot: fix every detected tool (admin path patches go via sudo)
sudo ./install-zscaler-trust-macos.sh --install --cert-file zscaler.pem --patch-all

# No-sudo path: write user-scope env vars and per-user tool configs only
./install-zscaler-trust-macos.sh --install --cert-file zscaler.pem \
    --patch-git --patch-npm --patch-aws --patch-gcloud --patch-pip --patch-curl

# Fetch from URLs
./install-zscaler-trust-macos.sh --install \
    --cert-url https://it.corp.example.com/root.cer \
    --patch-all

# Rollback all changes (system-keychain cleanup needs sudo)
sudo ./install-zscaler-trust-macos.sh --rollback --force
```

The macOS menu also exposes an extra `[L]` option to add certs to the **Login keychain** without admin — useful when you can't get sudo but still want Safari and Apple-framework tools to trust the Zscaler intercept in your user session. Option `[1]` (System keychain) still requires sudo.

### macOS Options

Same shape as the Linux options above, with these differences:

- `--shell` auto-detects to `zsh` (macOS default since Catalina).
- `--scope system` writes `/etc/zscaler-trust.sh` and sources it from `/etc/zprofile` and `/etc/profile`.
- `--patch-java` resolves `JAVA_HOME` via `/usr/libexec/java_home` if the env var is unset.

---

## Windows Usage

```powershell
# Interactive mode (audit + menu)
.\Install-ZscalerTrust.ps1

# Audit only
.\Install-ZscalerTrust.ps1 -Audit

# Non-interactive install — bundle + env vars only
.\Install-ZscalerTrust.ps1 -Install

# One-shot: fix every detected tool (also imports into LocalMachine\Root if elevated)
.\Install-ZscalerTrust.ps1 -Install -PatchAll

# Cherry-pick patches
.\Install-ZscalerTrust.ps1 -Install -PatchGit -PatchNpm -PatchAws -PatchGcloud -PatchPip

# Install certs into the Windows trust store (separately from -PatchAll)
.\Install-ZscalerTrust.ps1 -Install -InstallToCertStore     # admin -> LocalMachine\Root
.\Install-ZscalerTrust.ps1 -Install -InstallToCertStore     # non-admin -> CurrentUser\Root

# Machine-wide env-var scope (requires admin)
.\Install-ZscalerTrust.ps1 -Install -Scope Machine -PatchAll

# Fetch certs from one or more URLs
.\Install-ZscalerTrust.ps1 -Install -CertUrls @(
    'https://it.corp.example.com/root.cer',
    'https://internal-app.corp.example.com'
) -PatchAll

# Rollback all changes
.\Install-ZscalerTrust.ps1 -Rollback

# Force rollback without confirmation
.\Install-ZscalerTrust.ps1 -Rollback -Force
```

### Windows Parameters

```
Modes (mutually exclusive):
  -Audit                  Audit only, no changes
  -Install                Non-interactive install
  -Rollback               Undo all script-managed changes
  (no flag)               Audit + interactive menu

Cert sources:
  -CertUrls <string[]>    URLs to fetch certificates from
  -CertUrlTimeoutSec <n>  Per-URL timeout, seconds (default: 10)
  -BundleDir <path>       Output directory for bundles (default: %USERPROFILE%\certs)

Patch / install switches (only with -Install):
  -InstallToCertStore     Import to Cert:\LocalMachine\Root (admin) or
                          Cert:\CurrentUser\Root (no admin)
  -PatchAzureCli          Patch Azure CLI's bundled certifi cacert.pem
  -PatchGit               git config --global http.sslCAInfo
  -PatchNpm               npm config set cafile
  -PatchJava              keytool import into JVM cacerts (usually needs admin)
  -PatchAws               aws configure set default.ca_bundle
  -PatchGcloud            gcloud config set core/custom_ca_certs_file
  -PatchPip               pip config set global.cert (generic Python)
  -PatchCurl              Write cacert= block to %USERPROFILE%\_curlrc
  -PatchWget              Write ca_certificate= block to %USERPROFILE%\.wgetrc
  -PatchComposer          Write openssl.cafile= block to php.ini
  -PatchAll               Turn on every -Patch* flag plus -InstallToCertStore

Other:
  -TestConnection         Live TLS handshake test in audit
  -TestHost <hostname>    TLS test target (default: login.microsoftonline.com)
  -Scope User|Machine     Env var scope (default: User; Machine needs admin)
  -Force                  With -Rollback: skip the y/N confirmation prompt
```

---

## What Gets Configured

### Environment Variables

Each script writes a marker-fenced block (`# >>> Zscaler Trust Configuration ... >>>` / `... <<<`) so rollback can remove exactly what it added without disturbing other shell-profile contents.

| Variable | Used By |
|----------|---------|
| `REQUESTS_CA_BUNDLE` | Python `requests` library, AWS Boto, Databricks Connect |
| `SSL_CERT_FILE` | OpenSSL-based tools, Ruby/gem |
| `CURL_CA_BUNDLE` | curl |
| `NODE_EXTRA_CA_CERTS` | Node.js, npm, yarn |
| `PIP_CERT` | pip |

Scopes:
- **Linux user scope** — appended to `~/.bashrc` / `~/.zshrc`
- **Linux system scope** — `/etc/profile.d/zscaler-trust.sh`
- **macOS user scope** — appended to `~/.zshrc` / `~/.bash_profile`
- **macOS system scope** — `/etc/zscaler-trust.sh`, sourced from `/etc/zprofile` and `/etc/profile`
- **Windows User scope** — `[Environment]::SetEnvironmentVariable(..., 'User')`
- **Windows Machine scope** — `[Environment]::SetEnvironmentVariable(..., 'Machine')`

### Generated Files

| File | Description |
|------|-------------|
| `~/certs/zscaler-certs.pem` (or `%USERPROFILE%\certs\` on Windows) | Extracted Zscaler root certificate(s) |
| `~/certs/combined-ca-bundle.pem` | System CA bundle with Zscaler certs appended |

Both paths are configurable via `--bundle-dir` / `-BundleDir`.

---

## Certificate Sources

The scripts can discover Zscaler certificates from:

- **Windows Certificate Store** (PowerShell) -- `LocalMachine\Root`, `LocalMachine\CA`, `LocalMachine\AuthRoot`, `CurrentUser\Root`, `CurrentUser\CA`
- **macOS Keychains** -- `/Library/Keychains/System.keychain`, `~/Library/Keychains/login.keychain-db`, Apple's read-only System Roots keychain, `/etc/ssl/cert.pem`
- **Linux system trust store** -- `/etc/pki/ca-trust` (RHEL family) or `/usr/local/share/ca-certificates/` and `/etc/ssl/certs/ca-certificates.crt` (Debian family)
- **Local PEM/DER file** -- via `--cert-file` (bash scripts)
- **HTTP download** -- `.cer`, `.crt`, `.pem`, `.der` from a URL (auto-detects DER vs PEM)
- **TLS handshake capture** -- connect to a host and extract the CA portion of the presented chain

---

## Requirements

### Linux/Unix
- Bash, `openssl`, `awk`, `sed`, `grep`, `mktemp`
- `curl` or `wget` (only for `--cert-url`)
- Root access for `--scope system` and `--patch-java` (and `--patch-composer` if `php.ini` is in a system path)

### macOS
- macOS 10.15+ (Catalina or later)
- Bash 3.2+ or zsh 5+
- `openssl`, `security`, `awk`, `sed`, `grep`, `mktemp` — all in macOS base or Xcode Command Line Tools
- `sudo` for `--scope system`, System keychain install, or `--patch-java`
- Homebrew is detected if present but not required

### Windows
- PowerShell 5.0+
- Administrator privileges for `-Scope Machine`, `-InstallToCertStore` (when targeting LocalMachine), `-PatchAzureCli`, `-PatchJava`, or `-PatchComposer` if `php.ini` is in a system path
