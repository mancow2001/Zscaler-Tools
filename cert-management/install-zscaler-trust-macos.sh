#!/usr/bin/env bash
#
# install-zscaler-trust-macos.sh
#
# Audit and install Zscaler certificate trust for Python/Node/CLI tooling
# on macOS that doesn't honor the system Keychain. Provides feature parity
# with the Linux (install-zscaler-trust.sh) and Windows
# (Install-ZscalerTrust.ps1) scripts in this repository.
#
# Default (no flags): runs a read-only audit, then shows an interactive menu.
# --audit:    audit only, no menu, no changes
# --install:  non-interactive install (write bundle + set env vars)
# --rollback: detect and undo everything this script could have applied
#
# See --help for full usage.

set -uo pipefail

# ============================================================================
# Defaults & globals
# ============================================================================

MODE=""                    # audit | install | rollback | (empty = interactive)
TEST_CONNECTION=false
TEST_HOST="login.microsoftonline.com"
BUNDLE_DIR="$HOME/certs"
CERT_FILE=""
CERT_URLS=()               # array of URLs (repeatable --cert-url)
CERT_URL_TIMEOUT=10        # per-URL timeout in seconds
PATCH_AZURE_CLI=false
PATCH_GIT=false
PATCH_NPM=false
PATCH_JAVA=false
PATCH_AWS=false
PATCH_GCLOUD=false
PATCH_PIP=false
PATCH_CURL=false
PATCH_WGET=false
PATCH_COMPOSER=false
PATCH_ALL=false            # turns on every --patch-* flag
FORCE=false                # skip rollback confirmation
SCOPE="user"               # user | system
TARGET_SHELL=""             # bash | zsh | both | (empty = auto-detect)

SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"
SYSTEM_ROOTS_KEYCHAIN="/System/Library/Keychains/SystemRootCertificates.keychain"
LOGIN_KEYCHAIN=""           # resolved dynamically via `security login-keychain`
SYSTEM_CA_BUNDLE="/etc/ssl/cert.pem"

# Homebrew prefix (Apple Silicon = /opt/homebrew, Intel = /usr/local)
BREW_PREFIX=""

ZSCALER_MARKER="# --- Zscaler certificates appended by install-zscaler-trust-macos.sh ---"
PROFILE_MARKER_BEGIN="# >>> Zscaler Trust Configuration (managed by install-zscaler-trust-macos.sh) >>>"
PROFILE_MARKER_END="# <<< Zscaler Trust Configuration <<<"

ENV_VAR_NAMES=(REQUESTS_CA_BUNDLE SSL_CERT_FILE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS PIP_CERT)

# Temp files tracked for cleanup
TEMP_FILES=()

# Audit result globals
AUDIT_HAS_CERTS=false
AUDIT_HAS_URL_CERTS=false       # true if any certs came from --cert-url
AUDIT_ZSCALER_PEM=""            # path to temp file with Zscaler certs
AUDIT_AZURE_CLI_INSTALLED=false
AUDIT_AZURE_CLI_BUNDLE_OK=false
AUDIT_AZURE_CLI_PYTHON=""
AUDIT_AZURE_CLI_BUNDLE_PATH=""
AUDIT_PIP_SYSTEM_CERTS_OK=false
AUDIT_ENV_VARS_STATE="none-set" # ok | broken | none-set
AUDIT_COMBINED_BUNDLE_OK=false
AUDIT_SYSTEM_STORE_OK=false
AUDIT_GIT_CONFIGURED=false
AUDIT_NPM_CONFIGURED=false
AUDIT_JAVA_CONFIGURED=false
AUDIT_AWS_CLI_CONFIGURED=false
AUDIT_AWS_CLI_BUNDLE_VAL=""
AUDIT_GCLOUD_CONFIGURED=false
AUDIT_GCLOUD_BUNDLE_VAL=""
AUDIT_PIP_CONFIG_OK=false
AUDIT_PIP_CONFIG_VAL=""
AUDIT_CURL_RC_OK=false
AUDIT_WGET_RC_OK=false
AUDIT_COMPOSER_OK=false
AUDIT_COMPOSER_INI=""

# ============================================================================
# Helpers
# ============================================================================

cleanup() {
    for f in "${TEMP_FILES[@]+"${TEMP_FILES[@]}"}"; do
        rm -f "$f" 2>/dev/null
    done
}
trap cleanup EXIT

make_temp() {
    local t
    t=$(mktemp -t zscaler-trust)
    TEMP_FILES+=("$t")
    echo "$t"
}

is_root() {
    [[ $(id -u) -eq 0 ]]
}

command_exists() {
    command -v "$1" &>/dev/null
}

write_status() {
    local level="$1" msg="$2"
    case "$level" in
        OK)   printf "    \033[32m[+]\033[0m %s\n" "$msg" ;;
        FAIL) printf "    \033[31m[-]\033[0m %s\n" "$msg" ;;
        WARN) printf "    \033[33m[!]\033[0m %s\n" "$msg" ;;
        INFO) printf "    \033[90m[ ]\033[0m %s\n" "$msg" ;;
    esac
}

write_section() {
    printf "\n\033[36m==> %s\033[0m\n" "$1"
}

backup_file() {
    local src="$1"
    local backup="${src}.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$src" "$backup"
    echo "$backup"
}

# Check if a path looks like a bundle this script created
is_script_bundle() {
    local path="$1"
    [[ -z "$path" ]] && return 1
    local name
    name=$(basename "$path")
    [[ "$name" == "combined-ca-bundle.pem" || "$name" == "zscaler-certs.pem" ]]
}

# ============================================================================
# Dependency checks
# ============================================================================

check_dependencies() {
    local missing_required=()
    local missing_optional=()

    # Required dependencies - script cannot function without these
    local required_cmds=(openssl awk sed grep mktemp security)
    for cmd in "${required_cmds[@]}"; do
        if ! command_exists "$cmd"; then
            missing_required+=("$cmd")
        fi
    done

    # Conditionally required - needed based on flags
    if [[ ${#CERT_URLS[@]} -gt 0 ]]; then
        if ! command_exists curl && ! command_exists wget; then
            missing_required+=("curl or wget (needed for --cert-url)")
        fi
    fi

    if $TEST_CONNECTION || [[ ${#CERT_URLS[@]} -gt 0 ]]; then
        # macOS does not ship GNU coreutils' `timeout`. openssl s_client has its
        # own connect timeout; we'll degrade gracefully if `timeout` is missing.
        if ! command_exists timeout && ! command_exists gtimeout; then
            missing_optional+=("timeout (Homebrew coreutils; TLS operations will have no wall-clock timeout)")
        fi
    fi

    # Bail if any required dependencies are missing
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo ""
        printf "\033[31m================================\033[0m\n"
        printf "\033[31m  Missing Required Dependencies\033[0m\n"
        printf "\033[31m================================\033[0m\n"
        echo ""
        echo "    The following tools are required but not found on this system:"
        echo ""
        for dep in "${missing_required[@]}"; do
            printf "    \033[31m[-]\033[0m %s\n" "$dep"
        done
        echo ""
        echo "    All required tools are part of macOS or Xcode Command Line Tools."
        echo "    Install the Command Line Tools with:"
        echo ""
        echo "        xcode-select --install"
        echo ""
        echo "    Or install GNU equivalents via Homebrew:"
        echo ""
        echo "        brew install openssl coreutils gnu-sed grep gawk"
        echo ""
        exit 1
    fi

    # Warn about missing optional dependencies
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        for dep in "${missing_optional[@]}"; do
            write_status WARN "Optional dependency not found: $dep"
        done
    fi
}

# Resolve a timeout-prefix command if available (Homebrew coreutils ships gtimeout).
get_timeout_cmd() {
    local secs="$1"
    if command_exists timeout; then
        echo "timeout $secs"
    elif command_exists gtimeout; then
        echo "gtimeout $secs"
    fi
}

# ============================================================================
# Platform detection
# ============================================================================

detect_platform() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "Error: This script targets macOS. For Linux, use install-zscaler-trust.sh." >&2
        exit 1
    fi

    # Homebrew prefix (Apple Silicon vs Intel)
    if [[ -d /opt/homebrew ]]; then
        BREW_PREFIX="/opt/homebrew"
    elif [[ -d /usr/local/Homebrew ]] || [[ -x /usr/local/bin/brew ]]; then
        BREW_PREFIX="/usr/local"
    fi

    # Resolve current login keychain (path varies; .keychain-db on modern macOS).
    local lk
    lk=$(security login-keychain 2>/dev/null | tr -d '"' | awk 'NF{print; exit}')
    if [[ -n "$lk" ]]; then
        LOGIN_KEYCHAIN="$lk"
    elif [[ -f "$HOME/Library/Keychains/login.keychain-db" ]]; then
        LOGIN_KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"
    elif [[ -f "$HOME/Library/Keychains/login.keychain" ]]; then
        LOGIN_KEYCHAIN="$HOME/Library/Keychains/login.keychain"
    fi

    local arch
    arch=$(uname -m)
    local prod
    prod=$(sw_vers -productVersion 2>/dev/null || echo "?")
    write_status INFO "macOS $prod ($arch)${BREW_PREFIX:+, Homebrew: $BREW_PREFIX}"
}

# ============================================================================
# Certificate parsing helpers
# ============================================================================

# Check if a single PEM cert block (on stdin) has "Zscaler" in subject or issuer
cert_is_zscaler() {
    local pem_block="$1"
    local info
    info=$(echo "$pem_block" | openssl x509 -subject -issuer -noout 2>/dev/null) || return 1
    echo "$info" | grep -qi "Zscaler"
}

# Get CN from a PEM cert block
get_cert_cn() {
    local pem_block="$1"
    echo "$pem_block" | openssl x509 -subject -noout -nameopt multiline 2>/dev/null \
        | grep 'commonName' | sed 's/.*= //'
}

# Get expiry date from a PEM cert block
get_cert_expiry() {
    local pem_block="$1"
    echo "$pem_block" | openssl x509 -enddate -noout 2>/dev/null | sed 's/notAfter=//'
}

# Get SHA256 fingerprint from a PEM cert block
get_cert_fingerprint() {
    local pem_block="$1"
    echo "$pem_block" | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | sed 's/.*=//'
}

# Check if cert expires within N days
cert_expires_within_days() {
    local pem_block="$1" days="$2"
    local expiry expiry_epoch future_epoch
    expiry=$(echo "$pem_block" | openssl x509 -enddate -noout 2>/dev/null | sed 's/notAfter=//')
    [[ -z "$expiry" ]] && return 1
    # macOS BSD date: -j -f "format" "value" +%s
    expiry_epoch=$(date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null) || return 1
    future_epoch=$(date -v "+${days}d" +%s 2>/dev/null) || return 1
    [[ "$expiry_epoch" -lt "$future_epoch" ]]
}

# Iterate PEM blocks in a file and call a callback function name with each block as $1.
# Usage: foreach_pem_block FILE FUNC_NAME [extra args...]
foreach_pem_block() {
    local pem_file="$1"; shift
    local fn="$1"; shift
    [[ -f "$pem_file" ]] || return 1
    local cert_block="" in_cert=false
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                "$fn" "$cert_block" "$@"
                cert_block=""
            fi
        fi
    done < "$pem_file"
}

# ============================================================================
# Certificate discovery
# ============================================================================

# Extract Zscaler certs from a CA bundle file, write to output file
# Returns 0 if at least one cert found
extract_zscaler_from_bundle() {
    local bundle_path="$1" output_file="$2"
    local cert_block="" in_cert=false count=0

    [[ -f "$bundle_path" ]] || return 1

    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                if cert_is_zscaler "$cert_block"; then
                    printf "%s" "$cert_block" >> "$output_file"
                    ((count++))
                fi
                cert_block=""
            fi
        fi
    done < "$bundle_path"

    [[ $count -gt 0 ]]
}

# Extract Zscaler certs from a macOS keychain. Uses `security find-certificate
# -a -p` to dump all certs in PEM form, then filters for Zscaler.
# Returns 0 if at least one cert found.
extract_zscaler_from_keychain() {
    local keychain_path="$1" output_file="$2"
    local tmp count=0

    [[ -f "$keychain_path" ]] || return 1

    tmp=$(make_temp)
    security find-certificate -a -p "$keychain_path" >"$tmp" 2>/dev/null || return 1
    [[ -s "$tmp" ]] || return 1

    local cert_block="" in_cert=false
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                if cert_is_zscaler "$cert_block"; then
                    printf "%s" "$cert_block" >> "$output_file"
                    ((count++))
                fi
                cert_block=""
            fi
        fi
    done < "$tmp"

    [[ $count -gt 0 ]]
}

# Extract Zscaler certs from a live TLS connection
extract_zscaler_from_tls() {
    local host="$1" output_file="$2"
    local count=0

    command_exists openssl || return 1

    local chain_pem
    chain_pem=$(echo | openssl s_client -connect "${host}:443" -showcerts 2>/dev/null) || return 1

    local cert_block="" in_cert=false
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                if cert_is_zscaler "$cert_block"; then
                    printf "%s" "$cert_block" >> "$output_file"
                    ((count++))
                fi
                cert_block=""
            fi
        fi
    done <<< "$chain_pem"

    [[ $count -gt 0 ]]
}

# Download a file from a URL
download_file() {
    local url="$1" output_file="$2" timeout="${3:-10}"

    if command_exists curl; then
        curl -fsSL --connect-timeout "$timeout" --max-time "$timeout" -o "$output_file" "$url" 2>/dev/null
    elif command_exists wget; then
        wget -q --timeout="$timeout" -O "$output_file" "$url" 2>/dev/null
    else
        write_status FAIL "Neither curl nor wget available for download"
        return 1
    fi
}

# Try to convert a DER (binary) cert file to PEM, output to stdout
# Returns 0 if successful
try_der_to_pem() {
    local file="$1"
    openssl x509 -inform DER -in "$file" -outform PEM 2>/dev/null
}

# Retrieve certs from a single URL. Two strategies:
#   1. URL path ends in .cer/.crt/.pem/.der -> HTTP download, auto-detect DER vs PEM
#   2. Other https:// URLs -> TLS handshake, capture CA chain (skip leaf cert)
# Appends found certs to output_file. Returns count via CERTS_FROM_URL_COUNT.
CERTS_FROM_URL_COUNT=0

get_certs_from_url() {
    local url="$1" output_file="$2" timeout="${3:-10}"
    CERTS_FROM_URL_COUNT=0

    local is_cert_file=false
    if echo "$url" | grep -qiE '\.(cer|crt|pem|der)$'; then
        is_cert_file=true
    fi

    if $is_cert_file; then
        # Strategy 1: HTTP download
        local dl_file
        dl_file=$(make_temp)
        if ! download_file "$url" "$dl_file" "$timeout"; then
            write_status FAIL "Download failed: $url"
            return 1
        fi

        # Try DER first, fall back to PEM
        if try_der_to_pem "$dl_file" >> "$output_file" 2>/dev/null; then
            ((CERTS_FROM_URL_COUNT++))
        elif grep -q "BEGIN CERTIFICATE" "$dl_file" 2>/dev/null; then
            # It's PEM - extract individual certs
            local cert_block="" in_cert=false
            while IFS= read -r line; do
                if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                    in_cert=true
                    cert_block="$line"$'\n'
                elif [[ "$in_cert" == true ]]; then
                    cert_block+="$line"$'\n'
                    if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                        in_cert=false
                        printf "%s" "$cert_block" >> "$output_file"
                        ((CERTS_FROM_URL_COUNT++))
                        cert_block=""
                    fi
                fi
            done < "$dl_file"
        else
            write_status FAIL "File from $url is neither valid DER nor PEM"
            return 1
        fi
    else
        # Strategy 2: TLS handshake - capture CA chain (skip leaf at index 0)
        local scheme
        scheme=$(echo "$url" | sed 's|://.*||')
        if [[ "$scheme" != "https" && "$scheme" != "http" ]]; then
            write_status WARN "Unsupported URL scheme '$scheme' for $url"
            return 1
        fi

        local host port
        host=$(echo "$url" | sed 's|https\?://||' | sed 's|[:/].*||')
        port=$(echo "$url" | grep -oE ':[0-9]+' | head -1 | tr -d ':')
        [[ -z "$port" ]] && port=443

        command_exists openssl || { write_status FAIL "openssl not found"; return 1; }

        local chain_output
        local timeout_cmd
        timeout_cmd=$(get_timeout_cmd "$timeout")
        chain_output=$(echo | $timeout_cmd openssl s_client -connect "${host}:${port}" -showcerts 2>/dev/null) || {
            write_status FAIL "TLS handshake failed: $url"
            return 1
        }

        # Parse certs from chain, skip the first one (leaf/server cert)
        local cert_block="" in_cert=false cert_idx=0
        while IFS= read -r line; do
            if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                in_cert=true
                cert_block="$line"$'\n'
            elif [[ "$in_cert" == true ]]; then
                cert_block+="$line"$'\n'
                if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                    in_cert=false
                    if [[ $cert_idx -gt 0 ]]; then
                        # Skip leaf (index 0), keep CA certs
                        printf "%s" "$cert_block" >> "$output_file"
                        ((CERTS_FROM_URL_COUNT++))
                    fi
                    ((cert_idx++))
                    cert_block=""
                fi
            fi
        done <<< "$chain_output"
    fi

    return 0
}

# Retrieve certs from multiple URLs, deduplicate by fingerprint against
# already-found certs. Appends unique certs to output_file.
# Returns count of new unique certs via CERTS_FROM_URLS_COUNT.
CERTS_FROM_URLS_COUNT=0

get_certs_from_urls() {
    local output_file="$1" timeout="$2"
    shift 2
    local urls=("$@")
    CERTS_FROM_URLS_COUNT=0

    # Build newline-delimited list of already-known fingerprints for dedup
    local seen_fps=""
    if [[ -s "$output_file" ]]; then
        local cert_block="" in_cert=false
        while IFS= read -r line; do
            if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                in_cert=true
                cert_block="$line"$'\n'
            elif [[ "$in_cert" == true ]]; then
                cert_block+="$line"$'\n'
                if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                    in_cert=false
                    local fp
                    fp=$(get_cert_fingerprint "$cert_block")
                    [[ -n "$fp" ]] && seen_fps+="$fp"$'\n'
                    cert_block=""
                fi
            fi
        done < "$output_file"
    fi

    for url in "${urls[@]}"; do
        [[ -z "$url" ]] && continue
        printf "    \033[90mFetching: %s\033[0m\n" "$url"

        local per_url_tmp
        per_url_tmp=$(make_temp)
        if get_certs_from_url "$url" "$per_url_tmp" "$timeout"; then
            # Deduplicate against already-seen fingerprints
            local cert_block="" in_cert=false
            while IFS= read -r line; do
                if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                    in_cert=true
                    cert_block="$line"$'\n'
                elif [[ "$in_cert" == true ]]; then
                    cert_block+="$line"$'\n'
                    if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                        in_cert=false
                        local fp
                        fp=$(get_cert_fingerprint "$cert_block")
                        if [[ -n "$fp" ]] && ! echo "$seen_fps" | grep -qF "$fp"; then
                            seen_fps+="$fp"$'\n'
                            printf "%s" "$cert_block" >> "$output_file"
                            ((CERTS_FROM_URLS_COUNT++))
                        fi
                        cert_block=""
                    fi
                fi
            done < "$per_url_tmp"
        fi
    done

    return 0
}

# Main cert discovery: find Zscaler certs from any available source
find_zscaler_certs() {
    local output_file
    output_file=$(make_temp)

    # All status output goes to stderr; only the path goes to stdout
    # 1. --cert-file provided
    if [[ -n "$CERT_FILE" ]]; then
        if [[ ! -f "$CERT_FILE" ]]; then
            write_status FAIL "Certificate file not found: $CERT_FILE" >&2
            return 1
        fi

        # Auto-detect DER vs PEM format
        local pem_input="$CERT_FILE"
        if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" 2>/dev/null; then
            # Not PEM — try DER (binary) to PEM conversion
            local der_converted
            der_converted=$(make_temp)
            if try_der_to_pem "$CERT_FILE" > "$der_converted" 2>/dev/null && [[ -s "$der_converted" ]]; then
                write_status INFO "Converted DER format to PEM: $CERT_FILE" >&2
                pem_input="$der_converted"
            else
                write_status FAIL "File is neither valid PEM nor DER format: $CERT_FILE" >&2
                return 1
            fi
        fi

        local count=0 cert_block="" in_cert=false
        while IFS= read -r line; do
            if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                in_cert=true
                cert_block="$line"$'\n'
            elif [[ "$in_cert" == true ]]; then
                cert_block+="$line"$'\n'
                if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                    in_cert=false
                    if cert_is_zscaler "$cert_block"; then
                        printf "%s" "$cert_block" >> "$output_file"
                        ((count++))
                    fi
                    cert_block=""
                fi
            fi
        done < "$pem_input"
        # If no Zscaler-specific certs found, include all certs from the file
        if [[ $count -eq 0 ]]; then
            write_status WARN "No certs with 'Zscaler' in subject/issuer found in $CERT_FILE" >&2
            write_status INFO "Including all certificates from the file" >&2
            cp "$pem_input" "$output_file"
        fi
        echo "$output_file"
        return 0
    fi

    # 2. --cert-url provided
    if [[ ${#CERT_URLS[@]} -gt 0 ]]; then
        get_certs_from_urls "$output_file" "$CERT_URL_TIMEOUT" "${CERT_URLS[@]}" >&2
        if [[ -s "$output_file" ]]; then
            echo "$output_file"
            return 0
        fi
        write_status FAIL "No certificates retrieved from any URL" >&2
        return 1
    fi

    # 3. System keychain (admin-installed roots/intermediates)
    if extract_zscaler_from_keychain "$SYSTEM_KEYCHAIN" "$output_file"; then
        echo "$output_file"
        return 0
    fi

    # 4. Login keychain (per-user trust)
    if [[ -n "$LOGIN_KEYCHAIN" ]] && extract_zscaler_from_keychain "$LOGIN_KEYCHAIN" "$output_file"; then
        echo "$output_file"
        return 0
    fi

    # 5. System root certificates (read-only Apple-managed store)
    if extract_zscaler_from_keychain "$SYSTEM_ROOTS_KEYCHAIN" "$output_file"; then
        echo "$output_file"
        return 0
    fi

    # 6. System CA bundle (/etc/ssl/cert.pem - LibreSSL export of System Roots)
    if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
        if extract_zscaler_from_bundle "$SYSTEM_CA_BUNDLE" "$output_file"; then
            echo "$output_file"
            return 0
        fi
    fi

    # Nothing found
    return 1
}

# Count certs in a PEM file
count_pem_certs() {
    local pem_file="$1"
    local n
    n=$(grep -c "BEGIN CERTIFICATE" "$pem_file" 2>/dev/null) || true
    echo "${n:-0}"
}

# ============================================================================
# Bundle checking
# ============================================================================

# Check if a bundle file contains all certs from a Zscaler PEM file
# Sets BUNDLE_CHECK_FOUND and BUNDLE_CHECK_MISSING
BUNDLE_CHECK_FOUND=0
BUNDLE_CHECK_MISSING=0
BUNDLE_CHECK_MISSING_CNS=""

test_bundle_has_certs() {
    local bundle_path="$1" zscaler_pem="$2"
    BUNDLE_CHECK_FOUND=0
    BUNDLE_CHECK_MISSING=0
    BUNDLE_CHECK_MISSING_CNS=""

    [[ -f "$bundle_path" ]] || return 1

    local bundle_stripped
    bundle_stripped=$(tr -d '[:space:]' < "$bundle_path" 2>/dev/null) || return 1

    local cert_block="" in_cert=false
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                # Extract just the base64 portion for matching
                local b64
                b64=$(echo "$cert_block" | grep -v "^-----" | tr -d '[:space:]')
                if echo "$bundle_stripped" | grep -qF "$b64"; then
                    ((BUNDLE_CHECK_FOUND++))
                else
                    ((BUNDLE_CHECK_MISSING++))
                    local cn
                    cn=$(get_cert_cn "$cert_block")
                    if [[ -n "$BUNDLE_CHECK_MISSING_CNS" ]]; then
                        BUNDLE_CHECK_MISSING_CNS+=", $cn"
                    else
                        BUNDLE_CHECK_MISSING_CNS="$cn"
                    fi
                fi
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    return 0
}

# Check whether the system trust setting for a cert in a keychain has trustRoot.
# Returns 0 if cert is present and trusted.
keychain_cert_is_trusted() {
    local keychain="$1" cn="$2"
    # security find-certificate -c <CN> returns 0 if cert exists
    security find-certificate -c "$cn" "$keychain" &>/dev/null
}

# ============================================================================
# Azure CLI / Python interpreter discovery
# ============================================================================

# Locate Azure CLI's bundled Python interpreter on macOS.
# Azure CLI is typically installed via Homebrew or the official .pkg installer.
get_azure_cli_python() {
    local candidates=()
    [[ -n "$BREW_PREFIX" ]] && candidates+=(
        "$BREW_PREFIX/Cellar/azure-cli"/*/libexec/bin/python
        "$BREW_PREFIX/Cellar/azure-cli"/*/libexec/bin/python3
        "$BREW_PREFIX/opt/azure-cli/libexec/bin/python"
        "$BREW_PREFIX/opt/azure-cli/libexec/bin/python3"
    )
    # Official pkg installer path
    candidates+=(
        "/usr/local/microsoft/azure-cli/bin/python"
        "/usr/local/microsoft/azure-cli/bin/python3"
    )
    local p
    for p in "${candidates[@]}"; do
        if [[ -x "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# Locate Azure CLI's bundled certifi cacert.pem.
get_azure_cli_bundle() {
    local candidates=()
    [[ -n "$BREW_PREFIX" ]] && candidates+=(
        "$BREW_PREFIX/Cellar/azure-cli"/*/libexec/lib/python*/site-packages/certifi/cacert.pem
        "$BREW_PREFIX/opt/azure-cli/libexec/lib/python*/site-packages/certifi/cacert.pem"
    )
    candidates+=(
        "/usr/local/microsoft/azure-cli/lib/python*/site-packages/certifi/cacert.pem"
    )
    local p
    for p in "${candidates[@]}"; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# Find Python interpreters, output "label|path" lines
find_python_interpreters() {
    local az_py=""
    az_py=$(get_azure_cli_python 2>/dev/null || true)
    if [[ -n "$az_py" ]]; then
        echo "Azure CLI Python|$az_py"
    fi

    # Homebrew python3
    local seen=()
    [[ -n "$az_py" ]] && seen+=("$az_py")
    if [[ -n "$BREW_PREFIX" && -x "$BREW_PREFIX/bin/python3" ]]; then
        echo "Homebrew python3|$BREW_PREFIX/bin/python3"
        seen+=("$BREW_PREFIX/bin/python3")
    fi

    # python3 in PATH
    local sys_py
    sys_py=$(command -v python3 2>/dev/null || true)
    if [[ -n "$sys_py" ]]; then
        local skip=false
        local s
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$sys_py" == "$s" ]] && { skip=true; break; }
        done
        if ! $skip; then
            local label="python3 (PATH)"
            # Mark Apple's stub interpreter so the user knows
            if [[ "$sys_py" == "/usr/bin/python3" ]]; then
                label="python3 (Xcode CLT)"
            fi
            echo "$label|$sys_py"
            seen+=("$sys_py")
        fi
    fi

    # python in PATH (often a brewed venv)
    local py2
    py2=$(command -v python 2>/dev/null || true)
    if [[ -n "$py2" ]]; then
        local skip=false
        local s
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$py2" == "$s" ]] && { skip=true; break; }
        done
        if ! $skip; then
            echo "python (PATH)|$py2"
        fi
    fi
}

# Get certifi CA bundle path for a Python interpreter
get_certifi_path() {
    local python_exe="$1"
    "$python_exe" -c "import certifi; print(certifi.where())" 2>/dev/null || true
}

# Check if a pip package is installed
test_pip_package() {
    local python_exe="$1" package="$2"
    "$python_exe" -m pip show "$package" &>/dev/null
}

# ============================================================================
# Audit
# ============================================================================

run_audit() {
    echo ""
    printf "\033[36m================================\033[0m\n"
    printf "\033[36m  Zscaler Trust Audit (macOS)\033[0m\n"
    printf "\033[36m================================\033[0m\n"

    # Reset audit globals
    AUDIT_HAS_CERTS=false
    AUDIT_HAS_URL_CERTS=false
    AUDIT_ZSCALER_PEM=""
    AUDIT_AZURE_CLI_INSTALLED=false
    AUDIT_AZURE_CLI_BUNDLE_OK=false
    AUDIT_AZURE_CLI_PYTHON=""
    AUDIT_AZURE_CLI_BUNDLE_PATH=""
    AUDIT_PIP_SYSTEM_CERTS_OK=false
    AUDIT_ENV_VARS_STATE="none-set"
    AUDIT_COMBINED_BUNDLE_OK=false
    AUDIT_SYSTEM_STORE_OK=false
    AUDIT_GIT_CONFIGURED=false
    AUDIT_NPM_CONFIGURED=false
    AUDIT_JAVA_CONFIGURED=false

    # ---- 1. Keychain trust store ----
    write_section "[1] Keychain Trust Stores"

    local zscaler_pem
    zscaler_pem=$(make_temp)

    local found_system=false found_login=false found_roots=false found_in_bundle=false
    local keychain_source_label=""

    if extract_zscaler_from_keychain "$SYSTEM_KEYCHAIN" "$zscaler_pem"; then
        found_system=true
        keychain_source_label="System keychain ($SYSTEM_KEYCHAIN)"
    fi

    if ! $found_system && [[ -n "$LOGIN_KEYCHAIN" ]]; then
        if extract_zscaler_from_keychain "$LOGIN_KEYCHAIN" "$zscaler_pem"; then
            found_login=true
            keychain_source_label="Login keychain ($LOGIN_KEYCHAIN)"
        fi
    fi

    if ! $found_system && ! $found_login; then
        if extract_zscaler_from_keychain "$SYSTEM_ROOTS_KEYCHAIN" "$zscaler_pem"; then
            found_roots=true
            keychain_source_label="System roots ($SYSTEM_ROOTS_KEYCHAIN)"
        fi
    fi

    if ! $found_system && ! $found_login && ! $found_roots; then
        if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
            if extract_zscaler_from_bundle "$SYSTEM_CA_BUNDLE" "$zscaler_pem"; then
                found_in_bundle=true
                keychain_source_label="System CA bundle ($SYSTEM_CA_BUNDLE)"
            fi
        fi
    fi

    # Also try --cert-file if provided and nothing found yet
    if [[ ! -s "$zscaler_pem" && -n "$CERT_FILE" ]]; then
        if [[ -f "$CERT_FILE" ]]; then
            local pem_input="$CERT_FILE"
            if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" 2>/dev/null; then
                local der_converted
                der_converted=$(make_temp)
                if try_der_to_pem "$CERT_FILE" > "$der_converted" 2>/dev/null && [[ -s "$der_converted" ]]; then
                    write_status INFO "Converted DER format to PEM: $CERT_FILE"
                    pem_input="$der_converted"
                fi
            fi

            local cert_block="" in_cert=false
            while IFS= read -r line; do
                if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                    in_cert=true
                    cert_block="$line"$'\n'
                elif [[ "$in_cert" == true ]]; then
                    cert_block+="$line"$'\n'
                    if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                        in_cert=false
                        if cert_is_zscaler "$cert_block"; then
                            printf "%s" "$cert_block" >> "$zscaler_pem"
                        fi
                        cert_block=""
                    fi
                fi
            done < "$pem_input"
            # If no Zscaler-labeled certs, take all
            if [[ ! -s "$zscaler_pem" ]]; then
                cp "$pem_input" "$zscaler_pem"
            fi
            [[ -z "$keychain_source_label" ]] && keychain_source_label="--cert-file ($CERT_FILE)"
        fi
    fi

    # Also try --cert-url sources
    if [[ ${#CERT_URLS[@]} -gt 0 ]]; then
        echo ""
        printf "    \033[90mFrom --cert-url sources:\033[0m\n"
        local before_count
        before_count=$(count_pem_certs "$zscaler_pem" 2>/dev/null || echo 0)
        get_certs_from_urls "$zscaler_pem" "$CERT_URL_TIMEOUT" "${CERT_URLS[@]}"
        local after_count
        after_count=$(count_pem_certs "$zscaler_pem")
        local url_added=$((after_count - before_count))
        if [[ $url_added -gt 0 ]]; then
            write_status OK "Retrieved $url_added new cert(s) from URL sources"
            AUDIT_HAS_URL_CERTS=true
        else
            write_status INFO "No new certificates from URLs (all duplicates or fetches failed)"
        fi
    fi

    if [[ ! -s "$zscaler_pem" ]]; then
        write_status FAIL "No Zscaler certificates found"
        echo "        Zscaler certs may not be installed in any keychain."
        echo "        Use --cert-file or --cert-url to provide them."
        return
    fi

    AUDIT_HAS_CERTS=true
    AUDIT_ZSCALER_PEM="$zscaler_pem"

    # System trust store is "OK" only if certs are in the System keychain.
    # Login-only certs cover the user's apps but not system services like
    # /usr/bin/curl when run by other users.
    if $found_system; then
        AUDIT_SYSTEM_STORE_OK=true
    fi

    # Display found certs
    local cert_block="" in_cert=false
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                local cn expiry fingerprint
                cn=$(get_cert_cn "$cert_block")
                expiry=$(get_cert_expiry "$cert_block")
                fingerprint=$(get_cert_fingerprint "$cert_block")
                write_status OK "$cn"
                echo "        Source:      ${keychain_source_label:-provided file}"
                echo "        Expires:     $expiry"
                echo "        Fingerprint: $fingerprint"
                if cert_expires_within_days "$cert_block" 90 2>/dev/null; then
                    printf "        \033[33m<-- expires within 90 days!\033[0m\n"
                fi
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    if ! $found_system && ( $found_login || $found_roots || $found_in_bundle ); then
        echo ""
        write_status WARN "Certs found, but not in the System keychain"
        echo "        Some tools (e.g. /usr/bin/curl, Safari) trust System.keychain"
        echo "        rooted CAs by default. Use action [1] to add them there."
    fi

    # ---- 2. CA bundle files ----
    write_section "[2] CA Bundle Files"
    local has_any_bundle=false

    # System CA bundle (/etc/ssl/cert.pem)
    if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
        has_any_bundle=true
        test_bundle_has_certs "$SYSTEM_CA_BUNDLE" "$zscaler_pem"
        if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            write_status OK "System CA bundle"
            echo "        Path: $SYSTEM_CA_BUNDLE"
            echo "        Contains all $BUNDLE_CHECK_FOUND Zscaler cert(s)"
        elif [[ $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            write_status WARN "System CA bundle - partial"
            echo "        Path: $SYSTEM_CA_BUNDLE"
            echo "        Missing: $BUNDLE_CHECK_MISSING_CNS"
        else
            write_status FAIL "System CA bundle - no Zscaler certs"
            echo "        Path: $SYSTEM_CA_BUNDLE"
            echo "        Note: macOS regenerates this from the System Roots keychain;"
            echo "              installing to the System keychain typically updates it."
        fi
    fi

    # Azure CLI certifi
    local az_certifi=""
    az_certifi=$(get_azure_cli_bundle 2>/dev/null || true)
    if [[ -n "$az_certifi" ]]; then
        AUDIT_AZURE_CLI_INSTALLED=true
        AUDIT_AZURE_CLI_BUNDLE_PATH="$az_certifi"
        has_any_bundle=true
        test_bundle_has_certs "$az_certifi" "$zscaler_pem"
        local az_ok=false
        if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            az_ok=true
            write_status OK "Azure CLI certifi"
        elif [[ $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            write_status WARN "Azure CLI certifi - partial"
        else
            write_status FAIL "Azure CLI certifi - no Zscaler certs"
        fi
        echo "        Path: $az_certifi"
        AUDIT_AZURE_CLI_BUNDLE_OK=$az_ok
    fi
    AUDIT_AZURE_CLI_PYTHON=$(get_azure_cli_python 2>/dev/null || true)
    [[ -n "$AUDIT_AZURE_CLI_PYTHON" ]] && AUDIT_AZURE_CLI_INSTALLED=true

    # Python certifi bundles
    while IFS='|' read -r label pypath; do
        [[ -z "$pypath" ]] && continue
        local certifi_path
        certifi_path=$(get_certifi_path "$pypath")
        [[ -z "$certifi_path" || ! -f "$certifi_path" ]] && continue
        [[ "$certifi_path" == "$az_certifi" ]] && continue
        has_any_bundle=true
        test_bundle_has_certs "$certifi_path" "$zscaler_pem"
        if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            write_status OK "$label certifi"
        elif [[ $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            write_status WARN "$label certifi - partial"
            echo "        Missing: $BUNDLE_CHECK_MISSING_CNS"
        else
            write_status FAIL "$label certifi - no Zscaler certs"
        fi
        echo "        Path: $certifi_path"
    done < <(find_python_interpreters)

    # Combined bundle from this script
    local combined="$BUNDLE_DIR/combined-ca-bundle.pem"
    if [[ -f "$combined" ]]; then
        has_any_bundle=true
        test_bundle_has_certs "$combined" "$zscaler_pem"
        if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            AUDIT_COMBINED_BUNDLE_OK=true
            write_status OK "Combined CA bundle (this script)"
        elif [[ $BUNDLE_CHECK_FOUND -gt 0 ]]; then
            write_status WARN "Combined CA bundle - partial"
            echo "        Missing: $BUNDLE_CHECK_MISSING_CNS"
        else
            write_status FAIL "Combined CA bundle - no Zscaler certs"
        fi
        echo "        Path: $combined"
    fi

    if ! $has_any_bundle; then
        write_status INFO "No CA bundle files discovered"
    fi

    # ---- 3. Environment variables ----
    write_section "[3] Environment Variables"

    local env_ok=true any_env_set=false

    # Check current environment
    echo ""
    printf "    \033[90mCurrent environment:\033[0m\n"
    for var in "${ENV_VAR_NAMES[@]}"; do
        local val="${!var:-}"
        if [[ -z "$val" ]]; then
            printf "        \033[90m[ ] %s = (not set)\033[0m\n" "$var"
            continue
        fi
        any_env_set=true
        if [[ ! -f "$val" ]]; then
            write_status FAIL "$var = $val (file does not exist)"
            env_ok=false
            continue
        fi
        test_bundle_has_certs "$val" "$zscaler_pem"
        if [[ $BUNDLE_CHECK_MISSING -gt 0 ]]; then
            write_status WARN "$var = $val"
            echo "        Missing: $BUNDLE_CHECK_MISSING_CNS"
            env_ok=false
        else
            write_status OK "$var = $val"
        fi
    done

    # Check shell profile files for persistent settings
    echo ""
    printf "    \033[90mShell profile persistence:\033[0m\n"
    local profile_files=("$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile")
    local found_in_profile=false
    for pf in "${profile_files[@]}"; do
        if [[ -f "$pf" ]] && grep -q "$PROFILE_MARKER_BEGIN" "$pf" 2>/dev/null; then
            write_status OK "Zscaler env vars configured in $pf"
            found_in_profile=true
        fi
    done
    if [[ -f /etc/zprofile.d/zscaler-trust.sh ]] || [[ -f /etc/profile.d/zscaler-trust.sh ]]; then
        write_status OK "System-wide profile snippet present"
        found_in_profile=true
    fi
    if ! $found_in_profile; then
        write_status INFO "No Zscaler env var blocks found in shell profiles"
    fi

    # Check for dangerous override
    echo ""
    if [[ -n "${AZURE_CLI_DISABLE_CONNECTION_VERIFICATION:-}" ]]; then
        write_status WARN "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=$AZURE_CLI_DISABLE_CONNECTION_VERIFICATION - SSL verification DISABLED"
    fi

    if ! $any_env_set; then
        AUDIT_ENV_VARS_STATE="none-set"
    elif $env_ok; then
        AUDIT_ENV_VARS_STATE="ok"
    else
        AUDIT_ENV_VARS_STATE="broken"
    fi

    # ---- 4. Tool-specific configuration ----
    write_section "[4] Tool-Specific Configuration"

    # git
    if command_exists git; then
        local git_ssl
        git_ssl=$(git config --global http.sslCAInfo 2>/dev/null || true)
        if [[ -n "$git_ssl" ]]; then
            if [[ -f "$git_ssl" ]]; then
                test_bundle_has_certs "$git_ssl" "$zscaler_pem"
                if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                    write_status OK "git http.sslCAInfo = $git_ssl"
                    AUDIT_GIT_CONFIGURED=true
                else
                    write_status WARN "git http.sslCAInfo = $git_ssl (missing Zscaler certs)"
                fi
            else
                write_status FAIL "git http.sslCAInfo = $git_ssl (file does not exist)"
            fi
        else
            write_status INFO "git http.sslCAInfo not configured"
        fi
    else
        write_status INFO "git not found"
    fi

    # npm
    if command_exists npm; then
        local npm_ca
        npm_ca=$(npm config get cafile 2>/dev/null || true)
        if [[ -n "$npm_ca" && "$npm_ca" != "undefined" && "$npm_ca" != "null" ]]; then
            if [[ -f "$npm_ca" ]]; then
                test_bundle_has_certs "$npm_ca" "$zscaler_pem"
                if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                    write_status OK "npm cafile = $npm_ca"
                    AUDIT_NPM_CONFIGURED=true
                else
                    write_status WARN "npm cafile = $npm_ca (missing Zscaler certs)"
                fi
            else
                write_status FAIL "npm cafile = $npm_ca (file does not exist)"
            fi
        else
            write_status INFO "npm cafile not configured"
        fi
    else
        write_status INFO "npm not found"
    fi

    # curl config
    if [[ -f "$HOME/.curlrc" ]] && grep -q "^cacert" "$HOME/.curlrc" 2>/dev/null; then
        local curl_ca
        curl_ca=$(grep "^cacert" "$HOME/.curlrc" | head -1 | sed 's/^cacert[= ]*//')
        if [[ -f "$curl_ca" ]]; then
            test_bundle_has_certs "$curl_ca" "$zscaler_pem"
            if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                write_status OK "curl cacert in ~/.curlrc: $curl_ca"
                AUDIT_CURL_RC_OK=true
            else
                write_status WARN "curl cacert in ~/.curlrc: $curl_ca (missing Zscaler certs)"
            fi
        else
            write_status FAIL "curl cacert in ~/.curlrc: $curl_ca (file does not exist)"
        fi
    else
        write_status INFO "No curl cacert in ~/.curlrc"
    fi

    # wget config
    local wgetrc_found=false
    for wrc in "$HOME/.wgetrc" /etc/wgetrc "$BREW_PREFIX/etc/wgetrc"; do
        [[ -z "$wrc" ]] && continue
        if [[ -f "$wrc" ]] && grep -q "ca_certificate" "$wrc" 2>/dev/null; then
            local wget_ca
            wget_ca=$(grep "ca_certificate" "$wrc" | head -1 | sed 's/.*= *//')
            wgetrc_found=true
            if [[ "$wrc" == "$HOME/.wgetrc" && -f "$wget_ca" ]]; then
                test_bundle_has_certs "$wget_ca" "$zscaler_pem"
                if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                    write_status OK "wget ca_certificate in $wrc: $wget_ca"
                    AUDIT_WGET_RC_OK=true
                else
                    write_status WARN "wget ca_certificate in $wrc: $wget_ca (missing Zscaler certs)"
                fi
            else
                write_status INFO "wget ca_certificate in $wrc: $wget_ca"
            fi
        fi
    done
    if ! $wgetrc_found; then
        write_status INFO "No wget ca_certificate configured"
    fi

    # Java keystore
    local java_home="${JAVA_HOME:-}"
    if [[ -z "$java_home" ]] && command_exists /usr/libexec/java_home; then
        java_home=$(/usr/libexec/java_home 2>/dev/null || true)
    fi
    if command_exists keytool && [[ -n "$java_home" ]]; then
        local cacerts="$java_home/lib/security/cacerts"
        if [[ -f "$cacerts" ]]; then
            if keytool -list -keystore "$cacerts" -storepass changeit 2>/dev/null | grep -qi "zscaler"; then
                write_status OK "Java keystore contains Zscaler cert(s)"
                AUDIT_JAVA_CONFIGURED=true
            else
                write_status INFO "Java keystore does not contain Zscaler certs"
            fi
            echo "        Path: $cacerts"
        else
            write_status INFO "Java cacerts file not found at $cacerts"
        fi
    elif command_exists keytool; then
        write_status INFO "JAVA_HOME not set; skipping keystore check"
    else
        write_status INFO "keytool not found"
    fi

    # AWS CLI
    if command_exists aws; then
        local aws_ca
        aws_ca=$(get_aws_ca_bundle)
        if [[ -n "$aws_ca" ]]; then
            AUDIT_AWS_CLI_BUNDLE_VAL="$aws_ca"
            if [[ -f "$aws_ca" ]]; then
                test_bundle_has_certs "$aws_ca" "$zscaler_pem"
                if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                    write_status OK "aws default.ca_bundle = $aws_ca"
                    AUDIT_AWS_CLI_CONFIGURED=true
                else
                    write_status WARN "aws default.ca_bundle = $aws_ca (missing Zscaler certs)"
                fi
            else
                write_status FAIL "aws default.ca_bundle = $aws_ca (file does not exist)"
            fi
        else
            write_status INFO "aws default.ca_bundle not configured"
        fi
    else
        write_status INFO "aws CLI not found"
    fi

    # Google Cloud SDK
    if command_exists gcloud; then
        local gcloud_ca
        gcloud_ca=$(get_gcloud_ca_bundle)
        if [[ -n "$gcloud_ca" ]]; then
            AUDIT_GCLOUD_BUNDLE_VAL="$gcloud_ca"
            if [[ -f "$gcloud_ca" ]]; then
                test_bundle_has_certs "$gcloud_ca" "$zscaler_pem"
                if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                    write_status OK "gcloud core/custom_ca_certs_file = $gcloud_ca"
                    AUDIT_GCLOUD_CONFIGURED=true
                else
                    write_status WARN "gcloud core/custom_ca_certs_file = $gcloud_ca (missing Zscaler certs)"
                fi
            else
                write_status FAIL "gcloud core/custom_ca_certs_file = $gcloud_ca (file does not exist)"
            fi
        else
            write_status INFO "gcloud core/custom_ca_certs_file not configured"
        fi
    else
        write_status INFO "gcloud not found"
    fi

    # pip global.cert (generic, separate from Azure CLI's pip-system-certs)
    local pip_bin
    pip_bin=$(find_pip)
    if [[ -n "$pip_bin" ]]; then
        local pip_cert
        pip_cert=$(get_pip_config_cert)
        if [[ -n "$pip_cert" ]]; then
            AUDIT_PIP_CONFIG_VAL="$pip_cert"
            if [[ -f "$pip_cert" ]]; then
                test_bundle_has_certs "$pip_cert" "$zscaler_pem"
                if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                    write_status OK "$pip_bin global.cert = $pip_cert"
                    AUDIT_PIP_CONFIG_OK=true
                else
                    write_status WARN "$pip_bin global.cert = $pip_cert (missing Zscaler certs)"
                fi
            else
                write_status FAIL "$pip_bin global.cert = $pip_cert (file does not exist)"
            fi
        else
            write_status INFO "$pip_bin global.cert not configured"
        fi
    fi

    # Composer / PHP openssl.cafile
    if command_exists php; then
        local php_ini
        php_ini=$(get_php_ini)
        if [[ -n "$php_ini" && -f "$php_ini" ]]; then
            AUDIT_COMPOSER_INI="$php_ini"
            local php_ca
            php_ca=$(grep -i '^[[:space:]]*openssl\.cafile' "$php_ini" 2>/dev/null \
                | head -1 | sed 's/^[^=]*=[[:space:]]*//; s/^"//; s/"$//')
            if [[ -n "$php_ca" ]]; then
                if [[ -f "$php_ca" ]]; then
                    test_bundle_has_certs "$php_ca" "$zscaler_pem"
                    if [[ $BUNDLE_CHECK_MISSING -eq 0 && $BUNDLE_CHECK_FOUND -gt 0 ]]; then
                        write_status OK "PHP openssl.cafile = $php_ca"
                        AUDIT_COMPOSER_OK=true
                    else
                        write_status WARN "PHP openssl.cafile = $php_ca (missing Zscaler certs)"
                    fi
                else
                    write_status FAIL "PHP openssl.cafile = $php_ca (file does not exist)"
                fi
            else
                write_status INFO "PHP openssl.cafile not configured ($php_ini)"
            fi
        elif [[ -z "$php_ini" ]]; then
            write_status INFO "php found but no loaded php.ini"
        fi
    fi

    # ---- 5. Package managers ----
    write_section "[5] Package Managers"

    # Homebrew - delegates SSL to its bundled curl/openssl, which honors the
    # System keychain via Security framework on macOS.
    if command_exists brew; then
        if $AUDIT_SYSTEM_STORE_OK; then
            write_status OK "Homebrew uses the System keychain (Zscaler certs installed)"
        else
            write_status WARN "Homebrew uses the System keychain (Zscaler certs NOT installed there)"
            echo "        Install certs to the System keychain to fix brew SSL issues."
        fi
    fi

    # pip config file
    local pip_conf=""
    for pc in "$HOME/.pip/pip.conf" "$HOME/Library/Application Support/pip/pip.conf" \
              "$HOME/.config/pip/pip.conf" /etc/pip.conf; do
        if [[ -f "$pc" ]]; then
            pip_conf="$pc"
            break
        fi
    done
    if [[ -n "$pip_conf" ]]; then
        local pip_cert_val
        pip_cert_val=$(grep -i '^[[:space:]]*cert[[:space:]]*=' "$pip_conf" 2>/dev/null | head -1 | sed 's/.*=[[:space:]]*//')
        if [[ -n "$pip_cert_val" ]]; then
            if [[ -f "$pip_cert_val" ]]; then
                write_status OK "pip.conf cert = $pip_cert_val"
            else
                write_status FAIL "pip.conf cert = $pip_cert_val (file does not exist)"
            fi
            echo "        Config: $pip_conf"
        else
            write_status INFO "pip.conf found but no cert setting ($pip_conf)"
        fi
        # Check for trusted-host (SSL bypass)
        if grep -qi 'trusted-host' "$pip_conf" 2>/dev/null; then
            write_status WARN "pip.conf uses trusted-host (bypasses SSL verification)"
            echo "        Config: $pip_conf"
        fi
    else
        write_status INFO "No pip.conf found"
    fi

    # gem (Ruby)
    if command_exists gem; then
        if [[ -n "${SSL_CERT_FILE:-}" && -f "${SSL_CERT_FILE:-}" ]]; then
            write_status OK "gem uses SSL_CERT_FILE=$SSL_CERT_FILE"
        elif $AUDIT_SYSTEM_STORE_OK; then
            write_status OK "gem uses system trust store (Zscaler certs installed)"
        else
            write_status INFO "gem may need SSL_CERT_FILE set for Zscaler trust"
        fi
    else
        write_status INFO "gem not found"
    fi

    # ---- 6. Python trust-store bridges ----
    write_section "[6] Python Trust-Store Bridges"
    local found_python=false
    while IFS='|' read -r label pypath; do
        [[ -z "$pypath" ]] && continue
        found_python=true
        local has_psc=false has_ts=false
        if test_pip_package "$pypath" "pip-system-certs" 2>/dev/null; then
            has_psc=true
        fi
        if test_pip_package "$pypath" "truststore" 2>/dev/null; then
            has_ts=true
        fi

        if $has_psc; then
            write_status OK "$label: pip-system-certs installed"
        elif $has_ts; then
            write_status OK "$label: truststore installed"
        else
            write_status INFO "$label: no trust-store bridge installed"
        fi
        echo "        Path: $pypath"

        if [[ "$pypath" == "$AUDIT_AZURE_CLI_PYTHON" ]]; then
            AUDIT_PIP_SYSTEM_CERTS_OK=$has_psc
        fi
    done < <(find_python_interpreters)

    if ! $found_python; then
        write_status INFO "No Python interpreters discovered"
    fi

    if $AUDIT_HAS_URL_CERTS && $found_python; then
        echo ""
        write_status WARN "pip-system-certs reads only the system trust store"
        echo "        URL-sourced certs are NOT picked up by pip-system-certs."
        echo "        Use the bundle/env-var route or install URL certs into the"
        echo "        System keychain first if you need pip-system-certs to see them."
    fi

    # ---- 7. Live TLS test ----
    if $TEST_CONNECTION; then
        write_section "[7] Live TLS Test"
        run_tls_test "$TEST_HOST"
    fi
}

# ============================================================================
# TLS handshake test
# ============================================================================

run_tls_test() {
    local hostname="${1:-$TEST_HOST}"

    if ! command_exists openssl; then
        write_status FAIL "openssl not found"
        return 1
    fi

    echo "    Target: ${hostname}:443"
    local output
    output=$(echo | openssl s_client -connect "${hostname}:443" -showcerts 2>&1) || true

    # Extract TLS version and cipher
    local tls_version cipher
    tls_version=$(echo "$output" | grep "Protocol  :" | sed 's/.*: //' | head -1)
    cipher=$(echo "$output" | grep "Cipher    :" | sed 's/.*: //' | head -1)
    if [[ -n "$tls_version" ]]; then
        echo "    TLS:        $tls_version / $cipher"
    fi

    # Parse certificate chain
    echo "    Chain (as presented by server):"
    local cert_block="" in_cert=false cert_idx=0 chain_has_zscaler=false
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                local cn issuer
                cn=$(get_cert_cn "$cert_block")
                issuer=$(echo "$cert_block" | openssl x509 -issuer -noout -nameopt multiline 2>/dev/null \
                    | grep 'commonName' | sed 's/.*= //')
                echo "      [$cert_idx] $cn"
                echo "          Issuer:      $issuer"
                local fp
                fp=$(get_cert_fingerprint "$cert_block")
                echo "          Fingerprint: $fp"
                if cert_is_zscaler "$cert_block"; then
                    chain_has_zscaler=true
                fi
                ((cert_idx++))
                cert_block=""
            fi
        fi
    done <<< "$output"

    echo ""
    # Check verify result
    local verify_result
    verify_result=$(echo "$output" | grep "Verify return code:" | head -1)
    if echo "$verify_result" | grep -q "0 (ok)"; then
        write_status OK "OpenSSL trust store validates this chain"
        echo "        Note: openssl on macOS uses /etc/ssl/cert.pem by default."
        echo "        Apple frameworks (URLSession, Security.framework, /usr/bin/curl)"
        echo "        use the Keychain directly."
    else
        write_status WARN "Verify result: $verify_result"
    fi

    if $chain_has_zscaler; then
        write_status INFO "Zscaler IS intercepting this connection"
    else
        write_status INFO "Zscaler is NOT in the chain for this host"
    fi
}

# ============================================================================
# Action functions
# ============================================================================

# Install Zscaler certs into the macOS System keychain. Requires admin (sudo).
install_to_system_trust_store() {
    local zscaler_pem="$1"

    if ! is_root; then
        write_status FAIL "Installing to System keychain requires root (sudo). Skipping."
        return 1
    fi

    write_section "Installing to System keychain"

    local cert_block="" in_cert=false cert_idx=0 failures=0
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                local cn
                cn=$(get_cert_cn "$cert_block")
                local tmpf
                tmpf=$(make_temp)
                echo "$cert_block" > "$tmpf"

                # Add as a trusted root in the System keychain. -d = system domain,
                # -r trustRoot = trust as a root, -k = target keychain.
                if security add-trusted-cert -d -r trustRoot \
                        -k "$SYSTEM_KEYCHAIN" "$tmpf" 2>/dev/null; then
                    write_status OK "Installed to System keychain: $cn"
                else
                    write_status FAIL "Failed to install: $cn"
                    ((failures++))
                fi
                ((cert_idx++))
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    if [[ $failures -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Install Zscaler certs into the user's Login keychain. Does not require admin.
install_to_login_keychain() {
    local zscaler_pem="$1"

    if [[ -z "$LOGIN_KEYCHAIN" ]]; then
        write_status FAIL "Login keychain not found. Skipping."
        return 1
    fi

    write_section "Installing to Login keychain ($LOGIN_KEYCHAIN)"

    local cert_block="" in_cert=false failures=0
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                local cn
                cn=$(get_cert_cn "$cert_block")
                local tmpf
                tmpf=$(make_temp)
                echo "$cert_block" > "$tmpf"

                # -d omitted = user domain. May prompt for keychain password.
                if security add-trusted-cert -r trustRoot \
                        -k "$LOGIN_KEYCHAIN" "$tmpf" 2>/dev/null; then
                    write_status OK "Installed to Login keychain: $cn"
                else
                    write_status FAIL "Failed to install: $cn"
                    ((failures++))
                fi
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    [[ $failures -eq 0 ]]
}

# Write CA bundles to bundle directory
write_bundles() {
    local zscaler_pem="$1"

    mkdir -p "$BUNDLE_DIR"

    local zscaler_out="$BUNDLE_DIR/zscaler-certs.pem"
    local combined_out="$BUNDLE_DIR/combined-ca-bundle.pem"

    # All status output goes to stderr so stdout only has the return path
    write_section "Writing Zscaler PEM" >&2
    cp "$zscaler_pem" "$zscaler_out"
    printf "  \033[32m%s\033[0m\n" "$zscaler_out" >&2

    write_section "Building combined CA bundle" >&2

    # Find a base bundle
    local base_path=""

    # Prefer system CA bundle (/etc/ssl/cert.pem)
    if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
        base_path="$SYSTEM_CA_BUNDLE"
    fi

    # Fall back to System Roots keychain export
    if [[ -z "$base_path" ]]; then
        local roots_tmp
        roots_tmp=$(make_temp)
        if security find-certificate -a -p "$SYSTEM_ROOTS_KEYCHAIN" >"$roots_tmp" 2>/dev/null \
                && [[ -s "$roots_tmp" ]]; then
            base_path="$roots_tmp"
            echo "  base: System Roots keychain export" >&2
        fi
    fi

    # Fall back to Python certifi
    if [[ -z "$base_path" ]]; then
        while IFS='|' read -r label pypath; do
            [[ -z "$pypath" ]] && continue
            local cp_path
            cp_path=$(get_certifi_path "$pypath")
            if [[ -n "$cp_path" && -f "$cp_path" ]]; then
                base_path="$cp_path"
                break
            fi
        done < <(find_python_interpreters)
    fi

    if [[ -n "$base_path" ]]; then
        echo "  base: $base_path" >&2
        cp "$base_path" "$combined_out"
    else
        write_status WARN "No base CA bundle found. Using Zscaler certs only." >&2
        : > "$combined_out"
    fi

    # Check if already patched
    if grep -qF "$ZSCALER_MARKER" "$combined_out" 2>/dev/null; then
        write_status INFO "Combined bundle already contains Zscaler marker. Replacing..." >&2
        # Remove old Zscaler section
        local marker_line
        marker_line=$(grep -nF "$ZSCALER_MARKER" "$combined_out" | head -1 | cut -d: -f1)
        if [[ -n "$marker_line" ]]; then
            head -n "$((marker_line - 1))" "$combined_out" > "${combined_out}.tmp"
            mv "${combined_out}.tmp" "$combined_out"
        fi
    fi

    printf "\n%s\n" "$ZSCALER_MARKER" >> "$combined_out"
    cat "$zscaler_pem" >> "$combined_out"
    printf "  \033[32m%s\033[0m\n" "$combined_out" >&2

    # Only the path goes to stdout (for capture by callers)
    echo "$combined_out"
}

# Set environment variables in shell profiles
set_env_vars() {
    local bundle_path="$1" scope="${2:-user}"

    if [[ "$scope" == "system" ]]; then
        if ! is_root; then
            write_status FAIL "System scope requires root. Skipping."
            return 1
        fi

        write_section "Setting environment variables (system scope)"

        # macOS does not source /etc/profile.d/*.sh by default. Both bash and
        # zsh login shells DO source /etc/zprofile and /etc/profile, so we
        # append a snippet to /etc/zprofile (zsh is the default shell since
        # macOS Catalina) and source a single file from there.
        local sys_snippet="/etc/zscaler-trust.sh"

        cat > "$sys_snippet" << ENVEOF
$PROFILE_MARKER_BEGIN
export REQUESTS_CA_BUNDLE="$bundle_path"
export SSL_CERT_FILE="$bundle_path"
export CURL_CA_BUNDLE="$bundle_path"
export NODE_EXTRA_CA_CERTS="$bundle_path"
export PIP_CERT="$bundle_path"
$PROFILE_MARKER_END
ENVEOF
        chmod 644 "$sys_snippet"
        write_status OK "Written: $sys_snippet"

        for sys_profile in /etc/zprofile /etc/profile; do
            touch "$sys_profile"
            if ! grep -qF "source $sys_snippet" "$sys_profile" 2>/dev/null \
               && ! grep -qF ". $sys_snippet" "$sys_profile" 2>/dev/null; then
                {
                    echo ""
                    echo "$PROFILE_MARKER_BEGIN"
                    echo "[ -r $sys_snippet ] && . $sys_snippet"
                    echo "$PROFILE_MARKER_END"
                } >> "$sys_profile"
                write_status OK "Sourced from: $sys_profile"
            else
                write_status INFO "Already sourced from: $sys_profile"
            fi
        done

        # Also export in current shell
        export REQUESTS_CA_BUNDLE="$bundle_path"
        export SSL_CERT_FILE="$bundle_path"
        export CURL_CA_BUNDLE="$bundle_path"
        export NODE_EXTRA_CA_CERTS="$bundle_path"
        export PIP_CERT="$bundle_path"

        for var in "${ENV_VAR_NAMES[@]}"; do
            printf "  %-22s = %s\n" "$var" "$bundle_path"
        done
        return 0
    fi

    # User scope
    write_section "Setting environment variables (user scope)"

    local env_block
    env_block=$(cat << ENVEOF
$PROFILE_MARKER_BEGIN
export REQUESTS_CA_BUNDLE="$bundle_path"
export SSL_CERT_FILE="$bundle_path"
export CURL_CA_BUNDLE="$bundle_path"
export NODE_EXTRA_CA_CERTS="$bundle_path"
export PIP_CERT="$bundle_path"
$PROFILE_MARKER_END
ENVEOF
)

    # Determine target shell profiles. On macOS, bash login shells read
    # ~/.bash_profile (NOT ~/.bashrc) and zsh login shells read ~/.zprofile
    # while interactive shells read ~/.zshrc. We write to the interactive
    # files since `Terminal.app` runs login+interactive shells by default
    # and most users have aliases/env there.
    local target_profiles=()
    local detected_shell="${TARGET_SHELL}"

    if [[ -z "$detected_shell" ]]; then
        # Auto-detect: macOS default is zsh since Catalina (10.15)
        case "${SHELL:-/bin/zsh}" in
            */zsh)  detected_shell="zsh" ;;
            */bash) detected_shell="bash" ;;
            *)      detected_shell="zsh" ;;
        esac
    fi

    case "$detected_shell" in
        bash)
            target_profiles+=("$HOME/.bash_profile")
            ;;
        zsh)
            target_profiles+=("$HOME/.zshrc")
            ;;
        both)
            target_profiles+=("$HOME/.bash_profile" "$HOME/.zshrc")
            ;;
    esac

    for profile in "${target_profiles[@]}"; do
        # Create if it doesn't exist
        touch "$profile"

        # Remove existing marker block if present (literal-string match via awk;
        # BSD sed treats escaped parens as capture groups so a regex-based delete
        # silently misses markers that contain literal parens).
        if grep -qF "$PROFILE_MARKER_BEGIN" "$profile" 2>/dev/null; then
            local tmp_profile
            tmp_profile=$(make_temp)
            awk -v b="$PROFILE_MARKER_BEGIN" -v e="$PROFILE_MARKER_END" '
                $0 == b { skip = 1; next }
                skip    { if ($0 == e) skip = 0; next }
                        { print }
            ' "$profile" > "$tmp_profile" && cat "$tmp_profile" > "$profile"
        fi

        # Append new block
        printf "\n%s\n" "$env_block" >> "$profile"
        write_status OK "Updated: $profile"
    done

    # Export in current shell
    export REQUESTS_CA_BUNDLE="$bundle_path"
    export SSL_CERT_FILE="$bundle_path"
    export CURL_CA_BUNDLE="$bundle_path"
    export NODE_EXTRA_CA_CERTS="$bundle_path"
    export PIP_CERT="$bundle_path"

    for var in "${ENV_VAR_NAMES[@]}"; do
        printf "  %-22s = %s\n" "$var" "$bundle_path"
    done

    # Clear dangerous override if set
    if grep -rq "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION" "${target_profiles[@]}" 2>/dev/null; then
        write_status WARN "Consider removing AZURE_CLI_DISABLE_CONNECTION_VERIFICATION from your shell profile"
    fi

    return 0
}

# Patch Azure CLI's certifi bundle
patch_azure_cli() {
    local zscaler_pem="$1"

    local az_certifi
    az_certifi=$(get_azure_cli_bundle 2>/dev/null || true)

    if [[ -z "$az_certifi" ]]; then
        write_status WARN "Azure CLI certifi bundle not found. Skipping."
        return 1
    fi

    if [[ ! -w "$az_certifi" ]] && ! is_root; then
        write_status FAIL "Patching Azure CLI certifi requires root (or write access). Skipping."
        return 1
    fi

    write_section "Patching Azure CLI's certifi bundle"

    local az_marker="# Zscaler-appended-by-install-zscaler-trust"
    if grep -qF "$az_marker" "$az_certifi" 2>/dev/null; then
        printf "  \033[33mAlready patched (marker present). Skipping.\033[0m\n"
        return 0
    fi

    local backup
    backup=$(backup_file "$az_certifi")
    printf "\n%s\n" "$az_marker" >> "$az_certifi"
    cat "$zscaler_pem" >> "$az_certifi"
    printf "  \033[32mPatched. Backup: %s\033[0m\n" "$backup"
    return 0
}

# Configure git http.sslCAInfo
configure_git() {
    local bundle_path="$1"

    if ! command_exists git; then
        write_status INFO "git not found. Skipping."
        return 1
    fi

    write_section "Configuring git http.sslCAInfo"
    git config --global http.sslCAInfo "$bundle_path"
    write_status OK "git config --global http.sslCAInfo $bundle_path"
    return 0
}

# Configure npm cafile
configure_npm() {
    local bundle_path="$1"

    if ! command_exists npm; then
        write_status INFO "npm not found. Skipping."
        return 1
    fi

    write_section "Configuring npm cafile"
    npm config set cafile "$bundle_path"
    write_status OK "npm config set cafile $bundle_path"
    return 0
}

# Install pip-system-certs for a Python interpreter
install_pip_system_certs() {
    local python_exe="$1"

    if [[ -z "$python_exe" || ! -x "$python_exe" ]]; then
        write_status WARN "Python interpreter not found. Skipping."
        return 1
    fi

    if [[ ! -w "$(dirname "$python_exe")" ]] && ! is_root; then
        write_status FAIL "Installing pip-system-certs requires write access. Skipping."
        return 1
    fi

    write_section "Installing pip-system-certs in $python_exe"
    if "$python_exe" -m pip install pip-system-certs 2>&1; then
        write_status OK "Installed. Python now reads the system trust store directly."
        return 0
    else
        write_status FAIL "pip install failed"
        return 1
    fi
}

# Import certs into Java keystore
configure_java_keystore() {
    local zscaler_pem="$1"

    if ! command_exists keytool; then
        write_status INFO "keytool not found. Skipping."
        return 1
    fi

    local java_home="${JAVA_HOME:-}"
    if [[ -z "$java_home" ]] && command_exists /usr/libexec/java_home; then
        java_home=$(/usr/libexec/java_home 2>/dev/null || true)
    fi

    local cacerts=""
    if [[ -n "$java_home" && -f "$java_home/lib/security/cacerts" ]]; then
        cacerts="$java_home/lib/security/cacerts"
    else
        write_status WARN "JAVA_HOME not set or cacerts not found. Skipping."
        return 1
    fi

    if [[ ! -w "$cacerts" ]] && ! is_root; then
        write_status FAIL "Modifying Java keystore requires root. Skipping."
        return 1
    fi

    write_section "Importing Zscaler certs to Java keystore"

    local cert_block="" in_cert=false cert_idx=0
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=true
            cert_block="$line"$'\n'
        elif [[ "$in_cert" == true ]]; then
            cert_block+="$line"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                in_cert=false
                local cn
                cn=$(get_cert_cn "$cert_block")
                local alias_name
                alias_name=$(echo "$cn" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g')
                [[ -z "$alias_name" ]] && alias_name="zscaler-$cert_idx"

                local tmpf
                tmpf=$(make_temp)
                echo "$cert_block" > "$tmpf"

                # Check if already imported
                if keytool -list -keystore "$cacerts" -storepass changeit -alias "$alias_name" &>/dev/null; then
                    write_status INFO "Already in keystore: $alias_name ($cn)"
                else
                    if keytool -importcert -noprompt -keystore "$cacerts" -storepass changeit \
                        -alias "$alias_name" -file "$tmpf" 2>/dev/null; then
                        write_status OK "Imported: $alias_name ($cn)"
                    else
                        write_status FAIL "Failed to import: $alias_name ($cn)"
                    fi
                fi
                ((cert_idx++))
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    return 0
}

# ----------------------------------------------------------------------------
# Marker-fenced config-file helpers (curl ~/.curlrc, wget ~/.wgetrc, php.ini)
# ----------------------------------------------------------------------------

# Write a single-line directive inside a marker-fenced block, replacing any
# existing managed block. Uses `#` as the comment character (works for curlrc,
# wgetrc, php.ini, and most ini-style files).
write_managed_rcfile_block() {
    local target="$1" directive="$2"
    [[ -z "$target" || -z "$directive" ]] && return 1
    touch "$target" 2>/dev/null || return 1

    # Strip any existing managed block (literal-string match via awk).
    if grep -qF "$PROFILE_MARKER_BEGIN" "$target" 2>/dev/null; then
        local tmp
        tmp=$(make_temp)
        awk -v b="$PROFILE_MARKER_BEGIN" -v e="$PROFILE_MARKER_END" '
            $0 == b { skip = 1; next }
            skip    { if ($0 == e) skip = 0; next }
                    { print }
        ' "$target" > "$tmp" && cat "$tmp" > "$target"
    fi

    {
        echo ""
        echo "$PROFILE_MARKER_BEGIN"
        echo "$directive"
        echo "$PROFILE_MARKER_END"
    } >> "$target"
}

# Remove a managed block from a config file (used by rollback).
remove_managed_rcfile_block() {
    local target="$1"
    [[ -f "$target" ]] || return 1
    local tmp
    tmp=$(make_temp)
    awk -v b="$PROFILE_MARKER_BEGIN" -v e="$PROFILE_MARKER_END" '
        $0 == b { skip = 1; next }
        skip    { if ($0 == e) skip = 0; next }
                { print }
    ' "$target" > "$tmp" && cat "$tmp" > "$target"
}

# ----------------------------------------------------------------------------
# AWS CLI
# ----------------------------------------------------------------------------

# Return the current `default.ca_bundle` value from ~/.aws/config, or empty.
get_aws_ca_bundle() {
    local cfg="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
    [[ -f "$cfg" ]] || { echo ""; return; }
    # default profile section is `[default]`; the setting is `ca_bundle =`
    # under it. awk parses sections safely without depending on the aws CLI.
    awk '
        /^\[/ { section = $0; next }
        section == "[default]" && /^[[:space:]]*ca_bundle[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "")
            print
            exit
        }
    ' "$cfg"
}

configure_aws_cli() {
    local bundle_path="$1"

    if ! command_exists aws; then
        write_status INFO "AWS CLI not found. Skipping."
        return 1
    fi

    write_section "Configuring AWS CLI default.ca_bundle"
    if aws configure set default.ca_bundle "$bundle_path" 2>/dev/null; then
        write_status OK "aws configure set default.ca_bundle $bundle_path"
        return 0
    fi
    write_status FAIL "aws configure set default.ca_bundle failed"
    return 1
}

# ----------------------------------------------------------------------------
# Google Cloud SDK (gcloud)
# ----------------------------------------------------------------------------

get_gcloud_ca_bundle() {
    command_exists gcloud || { echo ""; return; }
    local val
    val=$(gcloud config get-value core/custom_ca_certs_file 2>/dev/null | tr -d '\r')
    # gcloud prints "(unset)" or empty when not configured
    [[ "$val" == "(unset)" || -z "$val" ]] && echo "" || echo "$val"
}

configure_gcloud() {
    local bundle_path="$1"

    if ! command_exists gcloud; then
        write_status INFO "gcloud not found. Skipping."
        return 1
    fi

    write_section "Configuring gcloud core/custom_ca_certs_file"
    if gcloud config set core/custom_ca_certs_file "$bundle_path" 2>/dev/null; then
        write_status OK "gcloud config set core/custom_ca_certs_file $bundle_path"
        return 0
    fi
    write_status FAIL "gcloud config set failed"
    return 1
}

# ----------------------------------------------------------------------------
# pip global.cert  (generic Python, not Azure CLI's bundled interpreter)
# ----------------------------------------------------------------------------

# Locate pip — prefer pip3, fall back to pip. Returns empty if neither exists.
find_pip() {
    if command_exists pip3; then
        echo "pip3"
    elif command_exists pip; then
        echo "pip"
    fi
}

get_pip_config_cert() {
    local pip
    pip=$(find_pip)
    [[ -z "$pip" ]] && { echo ""; return; }
    local val
    val=$("$pip" config get global.cert 2>/dev/null | tr -d '\r')
    # pip emits "ERROR: ..." to stdout when the key is unset on older versions
    [[ "$val" == ERROR:* ]] && val=""
    echo "$val"
}

configure_pip_global_cert() {
    local bundle_path="$1"
    local pip
    pip=$(find_pip)

    if [[ -z "$pip" ]]; then
        write_status INFO "pip / pip3 not found. Skipping."
        return 1
    fi

    write_section "Configuring pip global.cert"
    if "$pip" config set global.cert "$bundle_path" 2>/dev/null; then
        write_status OK "$pip config set global.cert $bundle_path"
        return 0
    fi
    write_status FAIL "$pip config set global.cert failed"
    return 1
}

# ----------------------------------------------------------------------------
# curl ~/.curlrc
# ----------------------------------------------------------------------------

configure_curl_rc() {
    local bundle_path="$1"

    if ! command_exists curl; then
        write_status INFO "curl not found. Skipping."
        return 1
    fi

    write_section "Configuring curl ~/.curlrc"
    write_managed_rcfile_block "$HOME/.curlrc" "cacert=$bundle_path"
    write_status OK "Wrote cacert= block to $HOME/.curlrc"
    return 0
}

# ----------------------------------------------------------------------------
# wget ~/.wgetrc
# ----------------------------------------------------------------------------

configure_wget_rc() {
    local bundle_path="$1"

    if ! command_exists wget; then
        write_status INFO "wget not found. Skipping."
        return 1
    fi

    write_section "Configuring wget ~/.wgetrc"
    write_managed_rcfile_block "$HOME/.wgetrc" "ca_certificate=$bundle_path"
    write_status OK "Wrote ca_certificate= block to $HOME/.wgetrc"
    return 0
}

# ----------------------------------------------------------------------------
# Composer (PHP)
# ----------------------------------------------------------------------------

# Locate the PHP loaded php.ini. `php --ini` prints a "Loaded Configuration
# File:" line whose value is the path (or "(none)").
get_php_ini() {
    command_exists php || { echo ""; return; }
    local ini
    ini=$(php --ini 2>/dev/null \
        | awk -F': *' '/^Loaded Configuration File/ {print $2; exit}' \
        | sed 's/[[:space:]]*$//')
    [[ "$ini" == "(none)" ]] && ini=""
    echo "$ini"
}

configure_composer_php() {
    local bundle_path="$1"

    if ! command_exists php; then
        write_status INFO "php not found. Skipping."
        return 1
    fi

    local ini
    ini=$(get_php_ini)
    if [[ -z "$ini" ]]; then
        write_status WARN "PHP is installed but has no loaded php.ini. Skipping."
        return 1
    fi

    if [[ ! -w "$ini" ]] && ! is_root; then
        write_status FAIL "PHP ini at $ini is not writable (try sudo). Skipping."
        return 1
    fi

    write_section "Configuring PHP openssl.cafile"
    write_managed_rcfile_block "$ini" "openssl.cafile=\"$bundle_path\""
    write_status OK "Wrote openssl.cafile= block to $ini"
    return 0
}

# ============================================================================
# Rollback
# ============================================================================

run_rollback() {
    local no_confirm="${1:-false}"
    local is_admin=false
    is_root && is_admin=true

    # Build rollback plan as parallel arrays
    local plan_kinds=()
    local plan_labels=()
    local plan_targets=()
    local plan_needs_admin=()
    local plan_extras=()    # extra data per item (env var name, scope, etc.)

    # ---- bundle files ----
    local zscaler_pem="$BUNDLE_DIR/zscaler-certs.pem"
    local combined_pem="$BUNDLE_DIR/combined-ca-bundle.pem"
    for file in "$zscaler_pem" "$combined_pem"; do
        if [[ -f "$file" ]]; then
            plan_kinds+=("DeleteFile")
            plan_labels+=("Delete bundle file")
            plan_targets+=("$file")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    done

    # ---- env vars in shell profiles (user scope) ----
    local profile_files=("$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile")
    for pf in "${profile_files[@]}"; do
        if [[ -f "$pf" ]] && grep -qF "$PROFILE_MARKER_BEGIN" "$pf" 2>/dev/null; then
            plan_kinds+=("RemoveProfileBlock")
            plan_labels+=("Remove env var block from shell profile")
            plan_targets+=("$pf")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    done

    # ---- env vars (system scope) ----
    if [[ -f /etc/zscaler-trust.sh ]]; then
        plan_kinds+=("DeleteFile")
        plan_labels+=("Delete system-wide env snippet")
        plan_targets+=("/etc/zscaler-trust.sh")
        plan_needs_admin+=(true)
        plan_extras+=("")
    fi
    for sys_profile in /etc/zprofile /etc/profile; do
        if [[ -f "$sys_profile" ]] && grep -qF "$PROFILE_MARKER_BEGIN" "$sys_profile" 2>/dev/null; then
            plan_kinds+=("RemoveProfileBlock")
            plan_labels+=("Remove sourcing block from system profile")
            plan_targets+=("$sys_profile")
            plan_needs_admin+=(true)
            plan_extras+=("")
        fi
    done

    # ---- current env vars pointing at our bundles ----
    for var in "${ENV_VAR_NAMES[@]}"; do
        local val="${!var:-}"
        if [[ -n "$val" ]] && is_script_bundle "$val"; then
            plan_kinds+=("UnsetEnvProcess")
            plan_labels+=("Unset env var (current process)")
            plan_targets+=("$var = $val")
            plan_needs_admin+=(false)
            plan_extras+=("$var")
        fi
    done

    # ---- Azure CLI cacert.pem patch ----
    local az_certifi=""
    az_certifi=$(get_azure_cli_bundle 2>/dev/null || true)
    if [[ -n "$az_certifi" ]]; then
        local az_marker="# Zscaler-appended-by-install-zscaler-trust"
        if grep -qF "$az_marker" "$az_certifi" 2>/dev/null; then
            plan_kinds+=("UnpatchAzureCli")
            plan_labels+=("Remove appended block from Azure CLI cacert.pem")
            plan_targets+=("$az_certifi")
            # Brew-installed paths may be user-writable; check needs.
            local needs=true
            [[ -w "$az_certifi" ]] && needs=false
            plan_needs_admin+=($needs)
            plan_extras+=("")
        fi
    fi

    # ---- pip-system-certs in Azure CLI Python ----
    local az_py=""
    az_py=$(get_azure_cli_python 2>/dev/null || true)
    if [[ -n "$az_py" ]] && test_pip_package "$az_py" "pip-system-certs" 2>/dev/null; then
        plan_kinds+=("UninstallPipSystemCerts")
        plan_labels+=("Uninstall pip-system-certs from Azure CLI Python")
        plan_targets+=("$az_py")
        local needs=true
        [[ -w "$(dirname "$az_py")" ]] && needs=false
        plan_needs_admin+=($needs)
        plan_extras+=("")
    fi

    # ---- git config ----
    if command_exists git; then
        local git_ssl
        git_ssl=$(git config --global http.sslCAInfo 2>/dev/null || true)
        if [[ -n "$git_ssl" ]] && is_script_bundle "$git_ssl"; then
            plan_kinds+=("UnsetGitConfig")
            plan_labels+=("Unset git http.sslCAInfo")
            plan_targets+=("http.sslCAInfo = $git_ssl")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    fi

    # ---- npm config ----
    if command_exists npm; then
        local npm_ca
        npm_ca=$(npm config get cafile 2>/dev/null || true)
        if [[ -n "$npm_ca" && "$npm_ca" != "undefined" && "$npm_ca" != "null" ]] && is_script_bundle "$npm_ca"; then
            plan_kinds+=("UnsetNpmConfig")
            plan_labels+=("Remove npm cafile config")
            plan_targets+=("cafile = $npm_ca")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    fi

    # ---- Java keystore ----
    local java_home="${JAVA_HOME:-}"
    if [[ -z "$java_home" ]] && command_exists /usr/libexec/java_home; then
        java_home=$(/usr/libexec/java_home 2>/dev/null || true)
    fi
    if command_exists keytool && [[ -n "$java_home" ]]; then
        local cacerts="$java_home/lib/security/cacerts"
        if [[ -f "$cacerts" ]] && keytool -list -keystore "$cacerts" -storepass changeit 2>/dev/null | grep -qi "zscaler"; then
            plan_kinds+=("RemoveJavaKeystoreCerts")
            plan_labels+=("Remove Zscaler certs from Java keystore")
            plan_targets+=("$cacerts")
            local needs=true
            [[ -w "$cacerts" ]] && needs=false
            plan_needs_admin+=($needs)
            plan_extras+=("")
        fi
    fi

    # ---- AWS CLI ----
    if command_exists aws; then
        local aws_ca
        aws_ca=$(get_aws_ca_bundle)
        if [[ -n "$aws_ca" ]] && is_script_bundle "$aws_ca"; then
            plan_kinds+=("UnsetAwsBundle")
            plan_labels+=("Remove AWS CLI default.ca_bundle")
            plan_targets+=("$aws_ca")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    fi

    # ---- gcloud ----
    if command_exists gcloud; then
        local gcloud_ca
        gcloud_ca=$(get_gcloud_ca_bundle)
        if [[ -n "$gcloud_ca" ]] && is_script_bundle "$gcloud_ca"; then
            plan_kinds+=("UnsetGcloudCaCerts")
            plan_labels+=("Unset gcloud core/custom_ca_certs_file")
            plan_targets+=("$gcloud_ca")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    fi

    # ---- pip global.cert (generic) ----
    local pip_bin
    pip_bin=$(find_pip)
    if [[ -n "$pip_bin" ]]; then
        local pip_cert
        pip_cert=$(get_pip_config_cert)
        if [[ -n "$pip_cert" ]] && is_script_bundle "$pip_cert"; then
            plan_kinds+=("UnsetPipGlobalCert")
            plan_labels+=("Unset pip global.cert")
            plan_targets+=("$pip_cert")
            plan_needs_admin+=(false)
            plan_extras+=("$pip_bin")
        fi
    fi

    # ---- curl ~/.curlrc ----
    if [[ -f "$HOME/.curlrc" ]] && grep -qF "$PROFILE_MARKER_BEGIN" "$HOME/.curlrc" 2>/dev/null; then
        plan_kinds+=("RemoveRcfileBlock")
        plan_labels+=("Remove managed block from ~/.curlrc")
        plan_targets+=("$HOME/.curlrc")
        plan_needs_admin+=(false)
        plan_extras+=("")
    fi

    # ---- wget ~/.wgetrc ----
    if [[ -f "$HOME/.wgetrc" ]] && grep -qF "$PROFILE_MARKER_BEGIN" "$HOME/.wgetrc" 2>/dev/null; then
        plan_kinds+=("RemoveRcfileBlock")
        plan_labels+=("Remove managed block from ~/.wgetrc")
        plan_targets+=("$HOME/.wgetrc")
        plan_needs_admin+=(false)
        plan_extras+=("")
    fi

    # ---- Composer / PHP openssl.cafile ----
    if command_exists php; then
        local php_ini
        php_ini=$(get_php_ini)
        if [[ -n "$php_ini" && -f "$php_ini" ]] && grep -qF "$PROFILE_MARKER_BEGIN" "$php_ini" 2>/dev/null; then
            plan_kinds+=("RemoveRcfileBlock")
            plan_labels+=("Remove managed block from $php_ini")
            plan_targets+=("$php_ini")
            local needs=true
            [[ -w "$php_ini" ]] && needs=false
            plan_needs_admin+=($needs)
            plan_extras+=("")
        fi
    fi

    # ---- Keychain certs (System and Login) ----
    # Find Zscaler-labeled certs in System keychain; require admin to remove.
    local sys_zscaler_tmp
    sys_zscaler_tmp=$(make_temp)
    if extract_zscaler_from_keychain "$SYSTEM_KEYCHAIN" "$sys_zscaler_tmp"; then
        plan_kinds+=("RemoveKeychainCerts")
        plan_labels+=("Remove Zscaler certs from System keychain")
        plan_targets+=("$SYSTEM_KEYCHAIN")
        plan_needs_admin+=(true)
        plan_extras+=("$sys_zscaler_tmp")
    fi

    # Login keychain - no admin needed but may need keychain unlock
    if [[ -n "$LOGIN_KEYCHAIN" ]]; then
        local login_zscaler_tmp
        login_zscaler_tmp=$(make_temp)
        if extract_zscaler_from_keychain "$LOGIN_KEYCHAIN" "$login_zscaler_tmp"; then
            plan_kinds+=("RemoveKeychainCerts")
            plan_labels+=("Remove Zscaler certs from Login keychain")
            plan_targets+=("$LOGIN_KEYCHAIN")
            plan_needs_admin+=(false)
            plan_extras+=("$login_zscaler_tmp")
        fi
    fi

    # ---- present plan ----
    write_section "Rollback Plan"
    if [[ ${#plan_kinds[@]} -eq 0 ]]; then
        write_status OK "Nothing to roll back. Trust setup is already clean."
        return
    fi

    local skip_count=0
    for i in "${!plan_kinds[@]}"; do
        local tag=""
        if ${plan_needs_admin[$i]} && ! $is_admin; then
            tag="   [needs root - will skip]"
            ((skip_count++))
        fi
        echo "    - ${plan_labels[$i]}$tag"
        printf "      \033[90m%s\033[0m\n" "${plan_targets[$i]}"
    done
    echo ""

    if [[ $skip_count -gt 0 ]]; then
        write_status WARN "$skip_count step(s) require root and will be skipped."
        echo "        Re-run with sudo to roll back those items."
        echo ""
    fi

    # ---- confirm ----
    if ! $no_confirm; then
        local resp
        read -rp "    Proceed with rollback? [y/N] " resp
        resp=$(echo "$resp" | tr '[:upper:]' '[:lower:]')
        if [[ "$resp" != "y" && "$resp" != "yes" ]]; then
            printf "    \033[90mAborted.\033[0m\n"
            return
        fi
    fi

    # ---- execute ----
    write_section "Executing rollback"
    for i in "${!plan_kinds[@]}"; do
        if ${plan_needs_admin[$i]} && ! $is_admin; then
            write_status WARN "Skipped (needs root): ${plan_labels[$i]}"
            continue
        fi

        case "${plan_kinds[$i]}" in
            DeleteFile)
                if rm -f "${plan_targets[$i]}"; then
                    write_status OK "Deleted: ${plan_targets[$i]}"
                else
                    write_status FAIL "Failed to delete: ${plan_targets[$i]}"
                fi
                ;;
            RemoveProfileBlock)
                local pf="${plan_targets[$i]}"
                local tmp_pf
                tmp_pf=$(make_temp)
                if awk -v b="$PROFILE_MARKER_BEGIN" -v e="$PROFILE_MARKER_END" '
                        $0 == b { skip = 1; next }
                        skip    { if ($0 == e) skip = 0; next }
                                { print }
                   ' "$pf" > "$tmp_pf" && cat "$tmp_pf" > "$pf"; then
                    write_status OK "Removed env var block from: $pf"
                else
                    write_status FAIL "Failed to edit: $pf"
                fi
                ;;
            UnsetEnvProcess)
                local var_name="${plan_extras[$i]}"
                unset "$var_name"
                write_status OK "Unset: $var_name (current process)"
                ;;
            UnpatchAzureCli)
                local az_file="${plan_targets[$i]}"
                local az_marker="# Zscaler-appended-by-install-zscaler-trust"
                local marker_line
                marker_line=$(grep -nF "$az_marker" "$az_file" | head -1 | cut -d: -f1)
                if [[ -n "$marker_line" ]]; then
                    local bak
                    bak=$(backup_file "$az_file")
                    head -n "$((marker_line - 1))" "$az_file" > "${az_file}.tmp"
                    mv "${az_file}.tmp" "$az_file"
                    # Add trailing newline
                    echo "" >> "$az_file"
                    write_status OK "Unpatched: $az_file"
                    echo "        Backup: $bak"
                else
                    write_status WARN "Marker not found (already removed?)"
                fi
                ;;
            UninstallPipSystemCerts)
                local py="${plan_targets[$i]}"
                if "$py" -m pip uninstall -y pip-system-certs 2>&1; then
                    write_status OK "Uninstalled pip-system-certs"
                else
                    write_status FAIL "pip uninstall failed"
                fi
                ;;
            UnsetGitConfig)
                if git config --global --unset http.sslCAInfo 2>/dev/null; then
                    write_status OK "Unset: git http.sslCAInfo"
                else
                    write_status FAIL "Failed to unset git config"
                fi
                ;;
            UnsetNpmConfig)
                if npm config delete cafile 2>/dev/null; then
                    write_status OK "Removed: npm cafile"
                else
                    write_status FAIL "Failed to remove npm cafile"
                fi
                ;;
            RemoveJavaKeystoreCerts)
                local cacerts="${plan_targets[$i]}"
                local aliases
                aliases=$(keytool -list -keystore "$cacerts" -storepass changeit 2>/dev/null \
                    | grep -i "zscaler" | sed 's/,.*//')
                while IFS= read -r alias_name; do
                    [[ -z "$alias_name" ]] && continue
                    if keytool -delete -keystore "$cacerts" -storepass changeit -alias "$alias_name" 2>/dev/null; then
                        write_status OK "Removed from keystore: $alias_name"
                    else
                        write_status FAIL "Failed to remove: $alias_name"
                    fi
                done <<< "$aliases"
                ;;
            UnsetAwsBundle)
                # Edit ~/.aws/config to remove the ca_bundle line under [default].
                local cfg="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
                if [[ -f "$cfg" ]]; then
                    local tmp
                    tmp=$(make_temp)
                    awk '
                        /^\[/ { section = $0; print; next }
                        section == "[default]" && /^[[:space:]]*ca_bundle[[:space:]]*=/ { next }
                                                { print }
                    ' "$cfg" > "$tmp" && cat "$tmp" > "$cfg"
                    write_status OK "Unset: aws default.ca_bundle"
                else
                    write_status WARN "AWS config not found: $cfg"
                fi
                ;;
            UnsetGcloudCaCerts)
                if gcloud config unset core/custom_ca_certs_file 2>/dev/null; then
                    write_status OK "Unset: gcloud core/custom_ca_certs_file"
                else
                    write_status FAIL "Failed to unset gcloud config"
                fi
                ;;
            UnsetPipGlobalCert)
                local pip_bin="${plan_extras[$i]}"
                if "$pip_bin" config unset global.cert 2>/dev/null; then
                    write_status OK "Unset: $pip_bin global.cert"
                else
                    write_status FAIL "Failed to unset $pip_bin global.cert"
                fi
                ;;
            RemoveRcfileBlock)
                local rc_path="${plan_targets[$i]}"
                if remove_managed_rcfile_block "$rc_path"; then
                    # If only whitespace remains, the file existed solely for our block.
                    if [[ ! -s "$rc_path" ]] || ! grep -q '[^[:space:]]' "$rc_path" 2>/dev/null; then
                        rm -f "$rc_path"
                        write_status OK "Removed (now empty): $rc_path"
                    else
                        write_status OK "Removed managed block from: $rc_path"
                    fi
                else
                    write_status FAIL "Failed to edit: $rc_path"
                fi
                ;;
            RemoveKeychainCerts)
                local keychain="${plan_targets[$i]}"
                local zscaler_tmp="${plan_extras[$i]}"
                # Iterate the Zscaler PEMs we extracted and remove each by SHA-1 hash.
                local cert_block="" in_cert=false
                while IFS= read -r line; do
                    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                        in_cert=true
                        cert_block="$line"$'\n'
                    elif [[ "$in_cert" == true ]]; then
                        cert_block+="$line"$'\n'
                        if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                            in_cert=false
                            local cn sha1
                            cn=$(get_cert_cn "$cert_block")
                            sha1=$(echo "$cert_block" | openssl x509 -fingerprint -sha1 -noout 2>/dev/null \
                                | sed 's/.*=//;s/://g')
                            local removed=false
                            # First try removing trust settings, then delete the cert.
                            if [[ -n "$sha1" ]]; then
                                # remove-trusted-cert requires a file; write temp and try
                                local tmpf
                                tmpf=$(make_temp)
                                echo "$cert_block" > "$tmpf"
                                security remove-trusted-cert -d "$tmpf" 2>/dev/null || true
                                if security delete-certificate -Z "$sha1" "$keychain" 2>/dev/null; then
                                    removed=true
                                fi
                            fi
                            if ! $removed && [[ -n "$cn" ]]; then
                                if security delete-certificate -c "$cn" "$keychain" 2>/dev/null; then
                                    removed=true
                                fi
                            fi
                            if $removed; then
                                write_status OK "Removed from keychain: $cn"
                            else
                                write_status FAIL "Failed to remove from keychain: $cn"
                            fi
                            cert_block=""
                        fi
                    fi
                done < "$zscaler_tmp"
                ;;
            *)
                write_status WARN "Unknown rollback kind: ${plan_kinds[$i]}"
                ;;
        esac
    done

    # Remove empty bundle directory
    if [[ -d "$BUNDLE_DIR" ]] && [[ -z "$(ls -A "$BUNDLE_DIR" 2>/dev/null)" ]]; then
        rmdir "$BUNDLE_DIR" 2>/dev/null && \
            write_status OK "Removed empty bundle directory: $BUNDLE_DIR"
    fi

    write_section "Rollback complete"
    echo "    Restart open shells / terminals to clear in-process env vars."
}

# ============================================================================
# Interactive menu
# ============================================================================

# Render the menu options (called after audit and after each action)
show_menu_options() {
    local is_admin="$1"
    local has_recommended=false
    ($needs_system_store || $needs_bundle || $needs_az_patch || $needs_git || $needs_npm || $needs_pip_certs || $needs_java || $needs_aws || $needs_gcloud || $needs_pip_cfg || $needs_curl_rc || $needs_wget_rc || $needs_composer) && has_recommended=true

    write_section "Suggested Next Steps"

    if ! $has_recommended; then
        printf "    \033[32mNo outstanding recommended actions for your current context.\033[0m\n"
        echo "    You can still run the TLS test, rollback, or quit."
    else
        echo "    Based on the audit, here's what would help:"
    fi
    echo ""

    # Count hidden admin items
    local hidden_count=0
    if ! $is_admin; then
        $needs_system_store && ((hidden_count++)) || true
        $AUDIT_AZURE_CLI_INSTALLED && $needs_az_patch && [[ ! -w "${AUDIT_AZURE_CLI_BUNDLE_PATH:-/dev/null}" ]] && ((hidden_count++)) || true
        $AUDIT_AZURE_CLI_INSTALLED && $needs_pip_certs && [[ ! -w "$(dirname "${AUDIT_AZURE_CLI_PYTHON:-/dev/null}")" ]] && ((hidden_count++)) || true
        command_exists keytool && $needs_java && ((hidden_count++)) || true
    fi

    if [[ $hidden_count -gt 0 ]]; then
        local plural="actions are"
        [[ $hidden_count -eq 1 ]] && plural="action is"
        printf "    \033[33mNote: %d admin-only %s hidden.\033[0m\n" "$hidden_count" "$plural"
        printf "    \033[33m      Re-run with sudo to access them.\033[0m\n"
        echo ""
    fi

    # [1] System keychain - requires admin
    if $is_admin || ! $needs_system_store; then
        if $is_admin; then
            if $needs_system_store; then
                echo "    [1] Install Zscaler certs to System keychain [recommended]"
            else
                printf "    \033[90m[1] Install Zscaler certs to System keychain\033[0m\n"
            fi
        fi
    fi

    # [L] Login keychain - never requires admin, always available
    if [[ -n "$LOGIN_KEYCHAIN" ]] && ! $AUDIT_SYSTEM_STORE_OK; then
        echo "    [L] Install Zscaler certs to Login keychain (per-user)"
    fi

    if $needs_bundle; then
        echo "    [2] Write combined CA bundle + set env vars (user scope) [recommended]"
    else
        printf "    \033[90m[2] Write combined CA bundle + set env vars (user scope)\033[0m\n"
    fi

    if $AUDIT_AZURE_CLI_INSTALLED; then
        local az_writable=true
        [[ -n "$AUDIT_AZURE_CLI_BUNDLE_PATH" && ! -w "$AUDIT_AZURE_CLI_BUNDLE_PATH" ]] && az_writable=false
        if $is_admin || $az_writable; then
            if $needs_az_patch; then
                echo "    [3] Patch Azure CLI certifi bundle [recommended]"
            else
                printf "    \033[90m[3] Patch Azure CLI certifi bundle\033[0m\n"
            fi
        fi
    fi

    if command_exists git; then
        if $needs_git; then
            echo "    [4] Configure git http.sslCAInfo [recommended]"
        else
            printf "    \033[90m[4] Configure git http.sslCAInfo\033[0m\n"
        fi
    fi

    if command_exists npm; then
        if $needs_npm; then
            echo "    [5] Configure npm cafile [recommended]"
        else
            printf "    \033[90m[5] Configure npm cafile\033[0m\n"
        fi
    fi

    if $AUDIT_AZURE_CLI_INSTALLED; then
        local az_py_writable=true
        [[ -n "$AUDIT_AZURE_CLI_PYTHON" && ! -w "$(dirname "$AUDIT_AZURE_CLI_PYTHON")" ]] && az_py_writable=false
        if $is_admin || $az_py_writable; then
            if $needs_pip_certs; then
                echo "    [6] Install pip-system-certs in Azure CLI Python [recommended]"
            else
                printf "    \033[90m[6] Install pip-system-certs in Azure CLI Python\033[0m\n"
            fi
        fi
    fi

    if command_exists keytool; then
        if $is_admin || ! $needs_java; then
            if $is_admin; then
                if $needs_java; then
                    echo "    [7] Import certs to Java keystore [recommended]"
                else
                    printf "    \033[90m[7] Import certs to Java keystore\033[0m\n"
                fi
            fi
        fi
    fi

    if command_exists aws; then
        if $needs_aws; then
            echo "    [8] Configure AWS CLI default.ca_bundle [recommended]"
        else
            printf "    \033[90m[8] Configure AWS CLI default.ca_bundle\033[0m\n"
        fi
    fi

    if command_exists gcloud; then
        if $needs_gcloud; then
            echo "    [9] Configure gcloud core/custom_ca_certs_file [recommended]"
        else
            printf "    \033[90m[9] Configure gcloud core/custom_ca_certs_file\033[0m\n"
        fi
    fi

    if [[ -n "$(find_pip)" ]]; then
        if $needs_pip_cfg; then
            echo "    [P] Configure pip global.cert (generic Python) [recommended]"
        else
            printf "    \033[90m[P] Configure pip global.cert (generic Python)\033[0m\n"
        fi
    fi

    if command_exists curl; then
        if $needs_curl_rc; then
            echo "    [C] Configure curl ~/.curlrc [recommended]"
        else
            printf "    \033[90m[C] Configure curl ~/.curlrc\033[0m\n"
        fi
    fi

    if command_exists wget; then
        if $needs_wget_rc; then
            echo "    [W] Configure wget ~/.wgetrc [recommended]"
        else
            printf "    \033[90m[W] Configure wget ~/.wgetrc\033[0m\n"
        fi
    fi

    if command_exists php; then
        if $needs_composer; then
            echo "    [H] Configure PHP openssl.cafile (Composer) [recommended]"
        else
            printf "    \033[90m[H] Configure PHP openssl.cafile (Composer)\033[0m\n"
        fi
    fi

    printf "    \033[90m[T] Run live TLS handshake test\033[0m\n"
    printf "    \033[90m[R] Roll back all script-managed changes\033[0m\n"
    if $has_recommended; then
        echo "    [A] Do all recommended actions"
    fi
    printf "    \033[90m[Q] Quit\033[0m\n"
    echo ""
}

show_interactive_menu() {
    if ! $AUDIT_HAS_CERTS; then
        write_section "No actions available"
        echo "    No Zscaler certs found. Use --cert-file or --cert-url to provide them,"
        echo "    or contact your IT/security team about certificate distribution."
        return
    fi

    local is_admin=false
    is_root && is_admin=true

    # Build action list based on audit findings
    local needs_system_store=false
    local needs_bundle=false
    local needs_az_patch=false
    local needs_git=false
    local needs_npm=false
    local needs_pip_certs=false
    local needs_java=false
    local needs_aws=false
    local needs_gcloud=false
    local needs_pip_cfg=false
    local needs_curl_rc=false
    local needs_wget_rc=false
    local needs_composer=false

    ! $AUDIT_SYSTEM_STORE_OK && needs_system_store=true
    [[ "$AUDIT_ENV_VARS_STATE" != "ok" ]] || ! $AUDIT_COMBINED_BUNDLE_OK && needs_bundle=true
    $AUDIT_AZURE_CLI_INSTALLED && ! $AUDIT_AZURE_CLI_BUNDLE_OK && needs_az_patch=true
    command_exists git && ! $AUDIT_GIT_CONFIGURED && needs_git=true
    command_exists npm && ! $AUDIT_NPM_CONFIGURED && needs_npm=true
    $AUDIT_AZURE_CLI_INSTALLED && ! $AUDIT_PIP_SYSTEM_CERTS_OK && needs_pip_certs=true
    command_exists aws && ! $AUDIT_AWS_CLI_CONFIGURED && needs_aws=true
    command_exists gcloud && ! $AUDIT_GCLOUD_CONFIGURED && needs_gcloud=true
    [[ -n "$(find_pip)" ]] && ! $AUDIT_PIP_CONFIG_OK && needs_pip_cfg=true
    command_exists curl && ! $AUDIT_CURL_RC_OK && needs_curl_rc=true
    command_exists wget && ! $AUDIT_WGET_RC_OK && needs_wget_rc=true
    command_exists php && [[ -n "$AUDIT_COMPOSER_INI" ]] && ! $AUDIT_COMPOSER_OK && needs_composer=true

    # Java
    local java_home="${JAVA_HOME:-}"
    if [[ -z "$java_home" ]] && command_exists /usr/libexec/java_home; then
        java_home=$(/usr/libexec/java_home 2>/dev/null || true)
    fi
    command_exists keytool && [[ -n "$java_home" ]] && ! $AUDIT_JAVA_CONFIGURED && needs_java=true

    show_menu_options "$is_admin"

    # Prompt loop
    local ran_something=false
    while true; do
        read -rp "    Your choice: " choice
        choice=$(echo "$choice" | tr '[:lower:]' '[:upper:]')
        [[ -z "$choice" ]] && continue
        ran_something=false

        case "$choice" in
            Q)
                printf "    \033[90mDone.\033[0m\n"
                return
                ;;
            T)
                local h
                read -rp "    Hostname [default: $TEST_HOST]: " h
                [[ -z "$h" ]] && h="$TEST_HOST"
                echo ""
                run_tls_test "$h"
                ran_something=true
                ;;
            R)
                run_rollback false
                ran_something=true
                ;;
            1)
                if ! $is_admin; then
                    write_status FAIL "Option [1] requires root. Re-run with sudo."
                else
                    if install_to_system_trust_store "$AUDIT_ZSCALER_PEM"; then
                        needs_system_store=false
                        AUDIT_SYSTEM_STORE_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            L)
                if [[ -z "$LOGIN_KEYCHAIN" ]]; then
                    write_status WARN "No login keychain detected."
                else
                    install_to_login_keychain "$AUDIT_ZSCALER_PEM" || true
                    ran_something=true
                fi
                ;;
            2)
                local combined_path
                combined_path=$(write_bundles "$AUDIT_ZSCALER_PEM")
                set_env_vars "$combined_path" "user"
                needs_bundle=false
                AUDIT_COMBINED_BUNDLE_OK=true
                AUDIT_ENV_VARS_STATE="ok"
                ran_something=true
                ;;
            3)
                if ! $AUDIT_AZURE_CLI_INSTALLED; then
                    write_status WARN "Option [3] is not available in this environment."
                else
                    if patch_azure_cli "$AUDIT_ZSCALER_PEM"; then
                        needs_az_patch=false
                        AUDIT_AZURE_CLI_BUNDLE_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            4)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_git "$bp"; then
                        needs_git=false
                        AUDIT_GIT_CONFIGURED=true
                    fi
                    ran_something=true
                fi
                ;;
            5)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_npm "$bp"; then
                        needs_npm=false
                        AUDIT_NPM_CONFIGURED=true
                    fi
                    ran_something=true
                fi
                ;;
            6)
                if ! $AUDIT_AZURE_CLI_INSTALLED; then
                    write_status WARN "Option [6] is not available in this environment."
                else
                    if install_pip_system_certs "$AUDIT_AZURE_CLI_PYTHON"; then
                        needs_pip_certs=false
                        AUDIT_PIP_SYSTEM_CERTS_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            7)
                if ! $is_admin; then
                    write_status FAIL "Option [7] requires root. Re-run with sudo."
                else
                    if configure_java_keystore "$AUDIT_ZSCALER_PEM"; then
                        needs_java=false
                        AUDIT_JAVA_CONFIGURED=true
                    fi
                    ran_something=true
                fi
                ;;
            8)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_aws_cli "$bp"; then
                        needs_aws=false; AUDIT_AWS_CLI_CONFIGURED=true
                    fi
                    ran_something=true
                fi
                ;;
            9)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_gcloud "$bp"; then
                        needs_gcloud=false; AUDIT_GCLOUD_CONFIGURED=true
                    fi
                    ran_something=true
                fi
                ;;
            P)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_pip_global_cert "$bp"; then
                        needs_pip_cfg=false; AUDIT_PIP_CONFIG_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            C)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_curl_rc "$bp"; then
                        needs_curl_rc=false; AUDIT_CURL_RC_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            W)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_wget_rc "$bp"; then
                        needs_wget_rc=false; AUDIT_WGET_RC_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            H)
                local bp="$BUNDLE_DIR/combined-ca-bundle.pem"
                if [[ ! -f "$bp" ]]; then
                    write_status WARN "Combined bundle not found. Run action [2] first."
                else
                    if configure_composer_php "$bp"; then
                        needs_composer=false; AUDIT_COMPOSER_OK=true
                    fi
                    ran_something=true
                fi
                ;;
            A)
                local has_recommended=false
                ($needs_system_store || $needs_bundle || $needs_az_patch || $needs_git || $needs_npm || $needs_pip_certs || $needs_java || $needs_aws || $needs_gcloud || $needs_pip_cfg || $needs_curl_rc || $needs_wget_rc || $needs_composer) && has_recommended=true

                if ! $has_recommended; then
                    write_status WARN "No recommended actions available in this context."
                    continue
                fi

                # Execute all recommended visible actions in order
                if $needs_system_store && $is_admin; then
                    if install_to_system_trust_store "$AUDIT_ZSCALER_PEM"; then
                        needs_system_store=false; AUDIT_SYSTEM_STORE_OK=true
                    fi
                fi

                local combined_path=""
                if $needs_bundle; then
                    combined_path=$(write_bundles "$AUDIT_ZSCALER_PEM")
                    set_env_vars "$combined_path" "user"
                    needs_bundle=false; AUDIT_COMBINED_BUNDLE_OK=true; AUDIT_ENV_VARS_STATE="ok"
                fi

                if $needs_az_patch; then
                    if patch_azure_cli "$AUDIT_ZSCALER_PEM"; then
                        needs_az_patch=false; AUDIT_AZURE_CLI_BUNDLE_OK=true
                    fi
                fi

                if $needs_git; then
                    local bp="${combined_path:-$BUNDLE_DIR/combined-ca-bundle.pem}"
                    if [[ -f "$bp" ]] && configure_git "$bp"; then
                        needs_git=false; AUDIT_GIT_CONFIGURED=true
                    fi
                fi

                if $needs_npm; then
                    local bp="${combined_path:-$BUNDLE_DIR/combined-ca-bundle.pem}"
                    if [[ -f "$bp" ]] && configure_npm "$bp"; then
                        needs_npm=false; AUDIT_NPM_CONFIGURED=true
                    fi
                fi

                if $needs_pip_certs; then
                    if install_pip_system_certs "$AUDIT_AZURE_CLI_PYTHON"; then
                        needs_pip_certs=false; AUDIT_PIP_SYSTEM_CERTS_OK=true
                    fi
                fi

                if $needs_java && $is_admin; then
                    if configure_java_keystore "$AUDIT_ZSCALER_PEM"; then
                        needs_java=false; AUDIT_JAVA_CONFIGURED=true
                    fi
                fi

                local bp="${combined_path:-$BUNDLE_DIR/combined-ca-bundle.pem}"
                if [[ -f "$bp" ]]; then
                    $needs_aws      && configure_aws_cli         "$bp" && { needs_aws=false;     AUDIT_AWS_CLI_CONFIGURED=true; }
                    $needs_gcloud   && configure_gcloud          "$bp" && { needs_gcloud=false;  AUDIT_GCLOUD_CONFIGURED=true; }
                    $needs_pip_cfg  && configure_pip_global_cert "$bp" && { needs_pip_cfg=false; AUDIT_PIP_CONFIG_OK=true; }
                    $needs_curl_rc  && configure_curl_rc         "$bp" && { needs_curl_rc=false; AUDIT_CURL_RC_OK=true; }
                    $needs_wget_rc  && configure_wget_rc         "$bp" && { needs_wget_rc=false; AUDIT_WGET_RC_OK=true; }
                    $needs_composer && configure_composer_php    "$bp" && { needs_composer=false; AUDIT_COMPOSER_OK=true; }
                fi

                write_section "All recommended actions complete"
                echo "    Restart open shells / terminals to pick up new env vars."
                return
                ;;
            *)
                write_status WARN "Invalid choice: $choice"
                ;;
        esac

        if $ran_something; then
            show_menu_options "$is_admin"
        fi
    done
}

# ============================================================================
# Non-interactive install
# ============================================================================

run_install() {
    # --patch-all expands to every individual --patch-* flag
    if $PATCH_ALL; then
        PATCH_AZURE_CLI=true
        PATCH_GIT=true
        PATCH_NPM=true
        PATCH_JAVA=true
        PATCH_AWS=true
        PATCH_GCLOUD=true
        PATCH_PIP=true
        PATCH_CURL=true
        PATCH_WGET=true
        PATCH_COMPOSER=true
    fi

    if [[ "$SCOPE" == "system" ]] && ! is_root; then
        echo "Error: --scope system requires root." >&2
        exit 1
    fi
    if $PATCH_AZURE_CLI && ! is_root; then
        local az_bundle
        az_bundle=$(get_azure_cli_bundle 2>/dev/null || true)
        if [[ -n "$az_bundle" && ! -w "$az_bundle" ]]; then
            echo "Error: --patch-azure-cli requires root (target not user-writable)." >&2
            exit 1
        fi
    fi

    write_section "Searching for Zscaler certificates"
    local zscaler_pem
    zscaler_pem=$(find_zscaler_certs)

    # Also fetch from URLs if provided
    if [[ ${#CERT_URLS[@]} -gt 0 ]]; then
        [[ -z "$zscaler_pem" ]] && zscaler_pem=$(make_temp)
        write_section "Fetching certificates from URLs"
        get_certs_from_urls "$zscaler_pem" "$CERT_URL_TIMEOUT" "${CERT_URLS[@]}"
        printf "\033[32mRetrieved %s cert(s) from URL sources\033[0m\n" "$CERTS_FROM_URLS_COUNT"
    fi

    if [[ -z "$zscaler_pem" || ! -s "$zscaler_pem" ]]; then
        echo "Error: No certificates available from any source. Use --cert-file or --cert-url." >&2
        exit 1
    fi

    local cert_count
    cert_count=$(count_pem_certs "$zscaler_pem")
    printf "\033[32mTotal: %s managed cert(s)\033[0m\n" "$cert_count"

    # Install to system trust store if root
    if is_root; then
        install_to_system_trust_store "$zscaler_pem" || true
    fi

    # Write bundles
    local combined_path
    combined_path=$(write_bundles "$zscaler_pem")

    # Set env vars
    set_env_vars "$combined_path" "$SCOPE"

    # Optional: patch Azure CLI
    if $PATCH_AZURE_CLI; then
        patch_azure_cli "$zscaler_pem" || true
    fi

    # Optional: configure git
    if $PATCH_GIT; then
        configure_git "$combined_path" || true
    fi

    # Optional: configure npm
    if $PATCH_NPM; then
        configure_npm "$combined_path" || true
    fi

    # Optional: import to Java keystore
    if $PATCH_JAVA; then
        configure_java_keystore "$zscaler_pem" || true
    fi

    # Optional: configure AWS CLI
    if $PATCH_AWS; then
        configure_aws_cli "$combined_path" || true
    fi

    # Optional: configure gcloud
    if $PATCH_GCLOUD; then
        configure_gcloud "$combined_path" || true
    fi

    # Optional: configure pip global.cert (generic Python)
    if $PATCH_PIP; then
        configure_pip_global_cert "$combined_path" || true
    fi

    # Optional: write curl ~/.curlrc
    if $PATCH_CURL; then
        configure_curl_rc "$combined_path" || true
    fi

    # Optional: write wget ~/.wgetrc
    if $PATCH_WGET; then
        configure_wget_rc "$combined_path" || true
    fi

    # Optional: configure PHP openssl.cafile (Composer)
    if $PATCH_COMPOSER; then
        configure_composer_php "$combined_path" || true
    fi

    write_section "Done"
    echo "Restart any open shells and terminals to pick up the new env vars."
    echo "Verify with: $0 --audit --test-connection"
}

# ============================================================================
# Usage
# ============================================================================

show_usage() {
    cat << 'USAGE'
Usage: install-zscaler-trust-macos.sh [OPTIONS]

Audit and install Zscaler certificate trust for CLI tools on macOS.

Modes (mutually exclusive):
  --audit              Audit only, no changes
  --install            Non-interactive install (write bundle + set env vars)
  --rollback           Detect and undo all script-managed changes
  (no flag)            Default: audit + interactive menu

Options:
  --cert-file FILE     PEM/DER file containing Zscaler cert(s) to import
  --cert-url URL       URL to fetch certs from (repeatable). Two strategies:
                         - URLs ending in .cer/.crt/.pem/.der: HTTP download
                           (auto-detects DER vs PEM format)
                         - Other https:// URLs: TLS handshake to capture the
                           CA chain (skips server leaf cert)
  --cert-url-timeout N Per-URL timeout in seconds (default: 10)
  --bundle-dir DIR     Output directory for PEM files (default: ~/certs)
  --test-connection    Include live TLS handshake test in audit
  --test-host HOST     TLS test target (default: login.microsoftonline.com)
  --patch-azure-cli    With --install: patch Azure CLI certifi bundle
  --patch-git          With --install: configure git http.sslCAInfo
  --patch-npm          With --install: configure npm cafile
  --patch-java         With --install: import certs into Java keystore (sudo)
  --patch-aws          With --install: set AWS CLI default.ca_bundle
  --patch-gcloud       With --install: set gcloud core/custom_ca_certs_file
  --patch-pip          With --install: set pip global.cert (generic Python)
  --patch-curl         With --install: write cacert= to ~/.curlrc
  --patch-wget         With --install: write ca_certificate= to ~/.wgetrc
  --patch-composer     With --install: write openssl.cafile= to php.ini (PHP)
  --patch-all          With --install: turn on every --patch-* flag above
  --force              With --rollback: skip the y/N confirmation prompt
  --scope user|system  Env var scope (default: user). System requires root.
  --shell bash|zsh|both  Target shell profile (default: auto-detect)
  -h, --help           Show this help

Discovery sources (in order, for default/audit/install when no --cert-* given):
  1. macOS System keychain          /Library/Keychains/System.keychain
  2. User Login keychain            ~/Library/Keychains/login.keychain-db
  3. Apple System Roots keychain    (read-only Apple-managed)
  4. System CA bundle file          /etc/ssl/cert.pem

Examples:
  ./install-zscaler-trust-macos.sh                                    # audit + menu
  ./install-zscaler-trust-macos.sh --audit                            # audit only
  ./install-zscaler-trust-macos.sh --audit --test-connection          # audit + TLS test
  ./install-zscaler-trust-macos.sh --install --cert-file zscaler.pem  # non-interactive
  sudo ./install-zscaler-trust-macos.sh --install --scope system      # system-wide
  ./install-zscaler-trust-macos.sh --rollback                         # interactive rollback
  ./install-zscaler-trust-macos.sh --rollback --force                 # rollback without prompt
  ./install-zscaler-trust-macos.sh --cert-url https://it.corp.example.com/root.cer
  ./install-zscaler-trust-macos.sh --cert-url https://proxy.corp.example.com \
                                   --cert-url https://it.corp.example.com/root.cer
USAGE
}

# ============================================================================
# Argument parsing
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit)
                [[ -n "$MODE" ]] && { echo "Error: Choose at most one of --audit, --install, --rollback." >&2; exit 1; }
                MODE="audit"
                shift
                ;;
            --install)
                [[ -n "$MODE" ]] && { echo "Error: Choose at most one of --audit, --install, --rollback." >&2; exit 1; }
                MODE="install"
                shift
                ;;
            --rollback)
                [[ -n "$MODE" ]] && { echo "Error: Choose at most one of --audit, --install, --rollback." >&2; exit 1; }
                MODE="rollback"
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --test-connection)
                TEST_CONNECTION=true
                shift
                ;;
            --test-host)
                TEST_HOST="${2:?--test-host requires a value}"
                shift 2
                ;;
            --bundle-dir)
                BUNDLE_DIR="${2:?--bundle-dir requires a value}"
                shift 2
                ;;
            --cert-file)
                CERT_FILE="${2:?--cert-file requires a value}"
                shift 2
                ;;
            --cert-url)
                CERT_URLS+=("${2:?--cert-url requires a value}")
                shift 2
                ;;
            --cert-url-timeout)
                CERT_URL_TIMEOUT="${2:?--cert-url-timeout requires a value}"
                shift 2
                ;;
            --patch-azure-cli)
                PATCH_AZURE_CLI=true
                shift
                ;;
            --patch-git)
                PATCH_GIT=true
                shift
                ;;
            --patch-npm)
                PATCH_NPM=true
                shift
                ;;
            --patch-java)
                PATCH_JAVA=true
                shift
                ;;
            --patch-aws)
                PATCH_AWS=true
                shift
                ;;
            --patch-gcloud)
                PATCH_GCLOUD=true
                shift
                ;;
            --patch-pip)
                PATCH_PIP=true
                shift
                ;;
            --patch-curl)
                PATCH_CURL=true
                shift
                ;;
            --patch-wget)
                PATCH_WGET=true
                shift
                ;;
            --patch-composer)
                PATCH_COMPOSER=true
                shift
                ;;
            --patch-all)
                PATCH_ALL=true
                shift
                ;;
            --scope)
                SCOPE="${2:?--scope requires a value}"
                if [[ "$SCOPE" != "user" && "$SCOPE" != "system" ]]; then
                    echo "Error: --scope must be 'user' or 'system'." >&2
                    exit 1
                fi
                shift 2
                ;;
            --shell)
                TARGET_SHELL="${2:?--shell requires a value}"
                if [[ "$TARGET_SHELL" != "bash" && "$TARGET_SHELL" != "zsh" && "$TARGET_SHELL" != "both" ]]; then
                    echo "Error: --shell must be 'bash', 'zsh', or 'both'." >&2
                    exit 1
                fi
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo "Error: Unknown option: $1" >&2
                show_usage >&2
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Main
# ============================================================================

main() {
    parse_args "$@"
    check_dependencies
    detect_platform

    case "$MODE" in
        audit)
            run_audit
            ;;
        install)
            run_install
            ;;
        rollback)
            run_rollback "$FORCE"
            ;;
        *)
            # Default: audit + interactive menu
            run_audit
            show_interactive_menu
            ;;
    esac
}

main "$@"
