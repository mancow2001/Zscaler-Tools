#!/usr/bin/env bash
#
# install-zscaler-trust.sh
#
# Audit and install Zscaler certificate trust for Python/Node/CLI tooling
# on Linux (RHEL/CentOS/Fedora and Debian/Ubuntu) that doesn't honor the
# system trust store.
#
# Default (no flags): runs a read-only audit, then shows an interactive menu.
# --audit:   audit only, no menu, no changes
# --install: non-interactive install (write bundle + set env vars)
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
FORCE=false                # skip rollback confirmation
SCOPE="user"               # user | system
TARGET_SHELL=""             # bash | zsh | both | (empty = auto-detect)

DISTRO_FAMILY=""            # rhel | debian
SYSTEM_TRUST_ANCHOR_DIR=""
UPDATE_CA_TRUST_CMD=""
SYSTEM_CA_BUNDLE=""

ZSCALER_MARKER="# --- Zscaler certificates appended by install-zscaler-trust.sh ---"
PROFILE_MARKER_BEGIN="# >>> Zscaler Trust Configuration (managed by install-zscaler-trust.sh) >>>"
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
AUDIT_PIP_SYSTEM_CERTS_OK=false
AUDIT_ENV_VARS_STATE="none-set" # ok | broken | none-set
AUDIT_COMBINED_BUNDLE_OK=false
AUDIT_SYSTEM_STORE_OK=false
AUDIT_GIT_CONFIGURED=false
AUDIT_NPM_CONFIGURED=false
AUDIT_JAVA_CONFIGURED=false

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
    t=$(mktemp)
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
    local required_cmds=(openssl awk sed grep mktemp)
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
        # timeout is used for TLS chain capture in cert-url and useful for TLS test
        if ! command_exists timeout; then
            missing_optional+=("timeout (from coreutils; TLS operations will have no timeout)")
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
        echo "    Install them using your package manager:"
        echo ""
        if command_exists apt-get; then
            echo "        sudo apt-get install openssl coreutils sed grep gawk"
        elif command_exists dnf; then
            echo "        sudo dnf install openssl coreutils sed grep gawk"
        elif command_exists yum; then
            echo "        sudo yum install openssl coreutils sed grep gawk"
        else
            echo "        Use your system package manager to install the missing tools."
        fi
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

# ============================================================================
# Distro detection
# ============================================================================

detect_distro() {
    local id="" id_like=""
    if [[ -f /etc/os-release ]]; then
        id=$(. /etc/os-release && echo "${ID:-}")
        id_like=$(. /etc/os-release && echo "${ID_LIKE:-}")
    fi

    case "$id" in
        rhel|centos|fedora|rocky|alma|ol)
            DISTRO_FAMILY="rhel" ;;
        debian|ubuntu|linuxmint|pop)
            DISTRO_FAMILY="debian" ;;
        *)
            if [[ "$id_like" == *rhel* ]] || [[ "$id_like" == *fedora* ]] || [[ "$id_like" == *centos* ]]; then
                DISTRO_FAMILY="rhel"
            elif [[ "$id_like" == *debian* ]] || [[ "$id_like" == *ubuntu* ]]; then
                DISTRO_FAMILY="debian"
            fi
            ;;
    esac

    # Fallback: detect by command/path presence
    if [[ -z "$DISTRO_FAMILY" ]]; then
        if command_exists update-ca-trust; then
            DISTRO_FAMILY="rhel"
        elif command_exists update-ca-certificates; then
            DISTRO_FAMILY="debian"
        else
            write_status WARN "Unknown distro. Will attempt best-effort detection."
            # Default to debian-style paths as a last resort
            DISTRO_FAMILY="debian"
        fi
    fi

    case "$DISTRO_FAMILY" in
        rhel)
            SYSTEM_TRUST_ANCHOR_DIR="/etc/pki/ca-trust/source/anchors"
            UPDATE_CA_TRUST_CMD="update-ca-trust"
            SYSTEM_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
            ;;
        debian)
            SYSTEM_TRUST_ANCHOR_DIR="/usr/local/share/ca-certificates/zscaler"
            UPDATE_CA_TRUST_CMD="update-ca-certificates"
            SYSTEM_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
            ;;
    esac

    write_status INFO "Detected distro family: $DISTRO_FAMILY"
}

# ============================================================================
# Certificate parsing helpers
# ============================================================================

# Split a PEM file into individual cert blocks, output each to stdout
# separated by a sentinel line
split_pem_certs() {
    local pem_file="$1"
    awk '/-----BEGIN CERTIFICATE-----/{block=""}
         /-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/{block=block $0 "\n"}
         /-----END CERTIFICATE-----/{printf "%s", block; print "---CERT-SEPARATOR---"}' "$pem_file"
}

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
    local expiry_epoch future_epoch
    expiry_epoch=$(echo "$pem_block" | openssl x509 -enddate -noout 2>/dev/null | sed 's/notAfter=//')
    expiry_epoch=$(date -d "$expiry_epoch" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_epoch" +%s 2>/dev/null) || return 1
    future_epoch=$(date -d "+${days} days" +%s 2>/dev/null || date -v "+${days}d" +%s 2>/dev/null) || return 1
    [[ "$expiry_epoch" -lt "$future_epoch" ]]
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

# Extract certs from trust anchor directory that were installed by this script.
# First checks for certs with "Zscaler" in subject/issuer (via openssl, not grep).
# Also checks for files matching our naming convention (zscaler-* or in zscaler/ subdir)
# since certs installed via --cert-file fallback may not have "Zscaler" in their subject.
extract_zscaler_from_anchors() {
    local anchor_dir="$1" output_file="$2"
    local count=0

    [[ -d "$anchor_dir" ]] || return 1

    local f
    for f in "$anchor_dir"/*.pem "$anchor_dir"/*.crt "$anchor_dir"/**/*.pem "$anchor_dir"/**/*.crt; do
        [[ -f "$f" ]] || continue
        # Parse every cert file with openssl (don't rely on text-grep of base64 PEM)
        local cert_block="" in_cert=false
        local fname
        fname=$(basename "$f")
        local is_our_file=false
        # Check if filename matches our naming convention (zscaler-*.pem/crt)
        [[ "$fname" == zscaler-* ]] && is_our_file=true
        # On Debian, anchor_dir is .../zscaler/, so any file in it is ours
        [[ "$anchor_dir" == */zscaler ]] && is_our_file=true

        while IFS= read -r line; do
            if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                in_cert=true
                cert_block="$line"$'\n'
            elif [[ "$in_cert" == true ]]; then
                cert_block+="$line"$'\n'
                if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                    in_cert=false
                    # Include if it has Zscaler in subject/issuer OR if it's in a file we created
                    if cert_is_zscaler "$cert_block" || $is_our_file; then
                        printf "%s" "$cert_block" >> "$output_file"
                        ((count++))
                    fi
                    cert_block=""
                fi
            fi
        done < "$f"
    done

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
        local timeout_cmd=""
        command_exists timeout && timeout_cmd="timeout $timeout"
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

    # 3. System CA bundle
    if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
        if extract_zscaler_from_bundle "$SYSTEM_CA_BUNDLE" "$output_file"; then
            echo "$output_file"
            return 0
        fi
    fi

    # 4. Trust anchor directory
    if extract_zscaler_from_anchors "$SYSTEM_TRUST_ANCHOR_DIR" "$output_file"; then
        echo "$output_file"
        return 0
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

# ============================================================================
# Python interpreter discovery
# ============================================================================

# Find Python interpreters, output "label|path" lines
find_python_interpreters() {
    local found=()

    # Azure CLI Python
    local az_py=""
    for p in /opt/az/bin/python3 /opt/az/bin/python; do
        if [[ -x "$p" ]]; then
            az_py="$p"
            echo "Azure CLI Python|$p"
            break
        fi
    done

    # System python3
    local sys_py
    sys_py=$(command -v python3 2>/dev/null || true)
    if [[ -n "$sys_py" && "$sys_py" != "$az_py" ]]; then
        echo "python3 (PATH)|$sys_py"
    fi

    # System python (if different)
    local py2
    py2=$(command -v python 2>/dev/null || true)
    if [[ -n "$py2" && "$py2" != "$sys_py" && "$py2" != "$az_py" ]]; then
        echo "python (PATH)|$py2"
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
    printf "\033[36m  Zscaler Trust Audit (Linux)\033[0m\n"
    printf "\033[36m================================\033[0m\n"

    # Reset audit globals
    AUDIT_HAS_CERTS=false
    AUDIT_HAS_URL_CERTS=false
    AUDIT_ZSCALER_PEM=""
    AUDIT_AZURE_CLI_INSTALLED=false
    AUDIT_AZURE_CLI_BUNDLE_OK=false
    AUDIT_AZURE_CLI_PYTHON=""
    AUDIT_PIP_SYSTEM_CERTS_OK=false
    AUDIT_ENV_VARS_STATE="none-set"
    AUDIT_COMBINED_BUNDLE_OK=false
    AUDIT_SYSTEM_STORE_OK=false
    AUDIT_GIT_CONFIGURED=false
    AUDIT_NPM_CONFIGURED=false
    AUDIT_JAVA_CONFIGURED=false

    # ---- 1. System trust store ----
    write_section "[1] System Trust Store"

    local zscaler_pem
    zscaler_pem=$(make_temp)

    local found_in_bundle=false found_in_anchors=false

    if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
        if extract_zscaler_from_bundle "$SYSTEM_CA_BUNDLE" "$zscaler_pem"; then
            found_in_bundle=true
        fi
    fi

    if ! $found_in_bundle; then
        if extract_zscaler_from_anchors "$SYSTEM_TRUST_ANCHOR_DIR" "$zscaler_pem"; then
            found_in_anchors=true
        fi
    fi

    # Also try --cert-file or --cert-url if provided and nothing found yet
    if [[ ! -s "$zscaler_pem" && -n "$CERT_FILE" ]]; then
        if [[ -f "$CERT_FILE" ]]; then
            # Auto-detect DER vs PEM format
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
        echo "        Zscaler certs may not be installed in the system trust store."
        echo "        Use --cert-file or --cert-url to provide them."
        return
    fi

    AUDIT_HAS_CERTS=true
    AUDIT_ZSCALER_PEM="$zscaler_pem"

    if $found_in_bundle || $found_in_anchors; then
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
                local source="provided file"
                if $found_in_bundle; then source="system bundle ($SYSTEM_CA_BUNDLE)"
                elif $found_in_anchors; then source="trust anchors ($SYSTEM_TRUST_ANCHOR_DIR)"
                fi
                write_status OK "$cn"
                echo "        Source:      $source"
                echo "        Expires:     $expiry"
                echo "        Fingerprint: $fingerprint"
                if cert_expires_within_days "$cert_block" 90 2>/dev/null; then
                    printf "        \033[33m<-- expires within 90 days!\033[0m\n"
                fi
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    # ---- 2. CA bundle files ----
    write_section "[2] CA Bundle Files"
    local has_any_bundle=false

    # System CA bundle
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
        fi
    fi

    # Azure CLI certifi
    local az_certifi=""
    for p in /opt/az/lib/python*/site-packages/certifi/cacert.pem; do
        if [[ -f "$p" ]]; then
            az_certifi="$p"
            break
        fi
    done
    if [[ -n "$az_certifi" ]]; then
        AUDIT_AZURE_CLI_INSTALLED=true
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
    # Azure CLI Python
    for p in /opt/az/bin/python3 /opt/az/bin/python; do
        if [[ -x "$p" ]]; then
            AUDIT_AZURE_CLI_PYTHON="$p"
            AUDIT_AZURE_CLI_INSTALLED=true
            break
        fi
    done

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
    local profile_files=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile")
    local found_in_profile=false
    for pf in "${profile_files[@]}"; do
        if [[ -f "$pf" ]] && grep -q "$PROFILE_MARKER_BEGIN" "$pf" 2>/dev/null; then
            write_status OK "Zscaler env vars configured in $pf"
            found_in_profile=true
        fi
    done
    if [[ -f /etc/profile.d/zscaler-trust.sh ]]; then
        write_status OK "System-wide: /etc/profile.d/zscaler-trust.sh"
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
        write_status INFO "curl cacert configured in ~/.curlrc: $curl_ca"
    else
        write_status INFO "No curl cacert in ~/.curlrc"
    fi

    # wget config
    local wgetrc_found=false
    for wrc in "$HOME/.wgetrc" /etc/wgetrc; do
        if [[ -f "$wrc" ]] && grep -q "ca_certificate" "$wrc" 2>/dev/null; then
            local wget_ca
            wget_ca=$(grep "ca_certificate" "$wrc" | head -1 | sed 's/.*= *//')
            write_status INFO "wget ca_certificate in $wrc: $wget_ca"
            wgetrc_found=true
        fi
    done
    if ! $wgetrc_found; then
        write_status INFO "No wget ca_certificate configured"
    fi

    # Java keystore
    if command_exists keytool && [[ -n "${JAVA_HOME:-}" ]]; then
        local cacerts="$JAVA_HOME/lib/security/cacerts"
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

    # ---- 5. Package managers ----
    write_section "[5] Package Managers"

    # apt (Debian/Ubuntu)
    if command_exists apt-get; then
        if $AUDIT_SYSTEM_STORE_OK; then
            write_status OK "apt uses system trust store (Zscaler certs installed)"
        else
            write_status WARN "apt uses system trust store (Zscaler certs NOT installed)"
            echo "        Install certs to system trust store to fix apt SSL issues"
        fi
        # Check for dangerous SSL verification overrides
        local apt_ssl_disabled=false
        for conf in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
            if [[ -f "$conf" ]] && grep -qi 'Verify-Peer.*false\|Verify-Host.*false' "$conf" 2>/dev/null; then
                write_status WARN "SSL verification disabled in $conf"
                apt_ssl_disabled=true
            fi
        done
        if ! $apt_ssl_disabled; then
            write_status OK "apt SSL verification not disabled"
        fi
    fi

    # yum/dnf (RHEL/CentOS/Fedora)
    if command_exists dnf || command_exists yum; then
        local pkg_mgr="yum"
        command_exists dnf && pkg_mgr="dnf"
        if $AUDIT_SYSTEM_STORE_OK; then
            write_status OK "$pkg_mgr uses system trust store (Zscaler certs installed)"
        else
            write_status WARN "$pkg_mgr uses system trust store (Zscaler certs NOT installed)"
            echo "        Install certs to system trust store to fix $pkg_mgr SSL issues"
        fi
        # Check for dangerous sslverify=0 override
        local yum_ssl_disabled=false
        for conf in /etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo; do
            if [[ -f "$conf" ]] && grep -qi '^sslverify[[:space:]]*=[[:space:]]*0\|^sslverify[[:space:]]*=[[:space:]]*false' "$conf" 2>/dev/null; then
                write_status WARN "SSL verification disabled in $conf (sslverify=0)"
                yum_ssl_disabled=true
            fi
        done
        if ! $yum_ssl_disabled; then
            write_status OK "$pkg_mgr SSL verification not disabled"
        fi
    fi

    # pip config file
    local pip_conf=""
    for pc in "$HOME/.pip/pip.conf" "$HOME/.config/pip/pip.conf" /etc/pip.conf; do
        if [[ -f "$pc" ]]; then
            pip_conf="$pc"
            break
        fi
    done
    if [[ -n "$pip_conf" ]]; then
        local pip_cert_val
        pip_cert_val=$(grep -i '^\s*cert\s*=' "$pip_conf" 2>/dev/null | head -1 | sed 's/.*=\s*//')
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
        echo "        system trust store first if you need pip-system-certs to see them."
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
        write_status OK "System trust store validates this chain"
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

# Install Zscaler certs into system trust store
install_to_system_trust_store() {
    local zscaler_pem="$1"

    if ! is_root; then
        write_status FAIL "Installing to system trust store requires root. Skipping."
        return 1
    fi

    write_section "Installing to system trust store"

    case "$DISTRO_FAMILY" in
        debian)
            mkdir -p "$SYSTEM_TRUST_ANCHOR_DIR"
            ;;
    esac

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
                # Slugify CN for filename, always prefixed with zscaler- for re-discovery
                local slug
                slug=$(echo "$cn" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//')
                # Ensure zscaler- prefix so extract_zscaler_from_anchors can find our files
                if [[ "$slug" != zscaler-* ]]; then
                    slug="zscaler-${slug}"
                fi
                [[ -z "$slug" || "$slug" == "zscaler-" ]] && slug="zscaler-cert-$cert_idx"

                local ext="pem"
                [[ "$DISTRO_FAMILY" == "debian" ]] && ext="crt"

                local dest="$SYSTEM_TRUST_ANCHOR_DIR/${slug}.${ext}"
                echo "$cert_block" > "$dest"
                write_status OK "Installed: $dest ($cn)"
                ((cert_idx++))
                cert_block=""
            fi
        fi
    done < "$zscaler_pem"

    # Run update command
    write_status INFO "Running $UPDATE_CA_TRUST_CMD ..."
    if $UPDATE_CA_TRUST_CMD; then
        write_status OK "System trust store updated"
    else
        write_status FAIL "$UPDATE_CA_TRUST_CMD failed"
        return 1
    fi

    # SELinux: restore context on RHEL
    if [[ "$DISTRO_FAMILY" == "rhel" ]] && command_exists restorecon && command_exists selinuxenabled; then
        if selinuxenabled 2>/dev/null; then
            restorecon -R "$SYSTEM_TRUST_ANCHOR_DIR" 2>/dev/null || true
            write_status INFO "SELinux context restored"
        fi
    fi

    return 0
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

    # Prefer system CA bundle
    if [[ -f "$SYSTEM_CA_BUNDLE" ]]; then
        base_path="$SYSTEM_CA_BUNDLE"
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
        local profile_d="/etc/profile.d/zscaler-trust.sh"

        cat > "$profile_d" << ENVEOF
$PROFILE_MARKER_BEGIN
export REQUESTS_CA_BUNDLE="$bundle_path"
export SSL_CERT_FILE="$bundle_path"
export CURL_CA_BUNDLE="$bundle_path"
export NODE_EXTRA_CA_CERTS="$bundle_path"
export PIP_CERT="$bundle_path"
$PROFILE_MARKER_END
ENVEOF
        chmod 644 "$profile_d"
        write_status OK "Written: $profile_d"

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

    # Determine target shell profiles
    local target_profiles=()
    local detected_shell="${TARGET_SHELL}"

    if [[ -z "$detected_shell" ]]; then
        # Auto-detect
        case "${SHELL:-/bin/bash}" in
            */zsh)  detected_shell="zsh" ;;
            */bash) detected_shell="bash" ;;
            *)      detected_shell="bash" ;;
        esac
    fi

    case "$detected_shell" in
        bash)
            [[ -f "$HOME/.bashrc" ]] && target_profiles+=("$HOME/.bashrc")
            [[ ! -f "$HOME/.bashrc" ]] && target_profiles+=("$HOME/.bashrc")
            ;;
        zsh)
            target_profiles+=("$HOME/.zshrc")
            ;;
        both)
            target_profiles+=("$HOME/.bashrc" "$HOME/.zshrc")
            ;;
    esac

    for profile in "${target_profiles[@]}"; do
        # Create if it doesn't exist
        touch "$profile"

        # Remove existing marker block if present
        if grep -qF "$PROFILE_MARKER_BEGIN" "$profile" 2>/dev/null; then
            # Use sed to remove the block between markers (inclusive)
            local escaped_begin escaped_end
            escaped_begin=$(printf '%s\n' "$PROFILE_MARKER_BEGIN" | sed 's/[[\.*^$()+?{|]/\\&/g')
            escaped_end=$(printf '%s\n' "$PROFILE_MARKER_END" | sed 's/[[\.*^$()+?{|]/\\&/g')
            sed -i.bak "/${escaped_begin}/,/${escaped_end}/d" "$profile"
            rm -f "${profile}.bak"
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

    local az_certifi=""
    for p in /opt/az/lib/python*/site-packages/certifi/cacert.pem; do
        if [[ -f "$p" ]]; then
            az_certifi="$p"
            break
        fi
    done

    if [[ -z "$az_certifi" ]]; then
        write_status WARN "Azure CLI certifi bundle not found. Skipping."
        return 1
    fi

    if [[ ! -w "$az_certifi" ]] && ! is_root; then
        write_status FAIL "Patching Azure CLI certifi requires root. Skipping."
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

    local cacerts=""
    if [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/lib/security/cacerts" ]]; then
        cacerts="$JAVA_HOME/lib/security/cacerts"
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
    local profile_files=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile")
    for pf in "${profile_files[@]}"; do
        if [[ -f "$pf" ]] && grep -qF "$PROFILE_MARKER_BEGIN" "$pf" 2>/dev/null; then
            plan_kinds+=("RemoveProfileBlock")
            plan_labels+=("Remove env var block from shell profile")
            plan_targets+=("$pf")
            plan_needs_admin+=(false)
            plan_extras+=("")
        fi
    done

    # ---- env vars in /etc/profile.d (system scope) ----
    if [[ -f /etc/profile.d/zscaler-trust.sh ]]; then
        plan_kinds+=("DeleteFile")
        plan_labels+=("Delete system-wide profile.d script")
        plan_targets+=("/etc/profile.d/zscaler-trust.sh")
        plan_needs_admin+=(true)
        plan_extras+=("")
    fi

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
    for p in /opt/az/lib/python*/site-packages/certifi/cacert.pem; do
        if [[ -f "$p" ]]; then
            az_certifi="$p"
            break
        fi
    done
    if [[ -n "$az_certifi" ]]; then
        local az_marker="# Zscaler-appended-by-install-zscaler-trust"
        if grep -qF "$az_marker" "$az_certifi" 2>/dev/null; then
            plan_kinds+=("UnpatchAzureCli")
            plan_labels+=("Remove appended block from Azure CLI cacert.pem")
            plan_targets+=("$az_certifi")
            plan_needs_admin+=(true)
            plan_extras+=("")
        fi
    fi

    # ---- pip-system-certs in Azure CLI Python ----
    local az_py=""
    for p in /opt/az/bin/python3 /opt/az/bin/python; do
        if [[ -x "$p" ]]; then
            az_py="$p"
            break
        fi
    done
    if [[ -n "$az_py" ]] && test_pip_package "$az_py" "pip-system-certs" 2>/dev/null; then
        plan_kinds+=("UninstallPipSystemCerts")
        plan_labels+=("Uninstall pip-system-certs from Azure CLI Python")
        plan_targets+=("$az_py")
        plan_needs_admin+=(true)
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
    if command_exists keytool && [[ -n "${JAVA_HOME:-}" ]]; then
        local cacerts="$JAVA_HOME/lib/security/cacerts"
        if [[ -f "$cacerts" ]] && keytool -list -keystore "$cacerts" -storepass changeit 2>/dev/null | grep -qi "zscaler"; then
            plan_kinds+=("RemoveJavaKeystoreCerts")
            plan_labels+=("Remove Zscaler certs from Java keystore")
            plan_targets+=("$cacerts")
            plan_needs_admin+=(true)
            plan_extras+=("")
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
                local escaped_begin escaped_end
                escaped_begin=$(printf '%s\n' "$PROFILE_MARKER_BEGIN" | sed 's/[[\.*^$()+?{|]/\\&/g')
                escaped_end=$(printf '%s\n' "$PROFILE_MARKER_END" | sed 's/[[\.*^$()+?{|]/\\&/g')
                if sed -i.bak "/${escaped_begin}/,/${escaped_end}/d" "$pf" 2>/dev/null; then
                    rm -f "${pf}.bak"
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
                # Find and remove Zscaler aliases
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
    # These are read from the caller's scope
    local has_recommended=false
    ($needs_system_store || $needs_bundle || $needs_az_patch || $needs_git || $needs_npm || $needs_pip_certs || $needs_java) && has_recommended=true

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
        $AUDIT_AZURE_CLI_INSTALLED && $needs_az_patch && ((hidden_count++)) || true
        $AUDIT_AZURE_CLI_INSTALLED && $needs_pip_certs && ((hidden_count++)) || true
        command_exists keytool && [[ -n "${JAVA_HOME:-}" ]] && $needs_java && ((hidden_count++)) || true
    fi

    if [[ $hidden_count -gt 0 ]]; then
        local plural="actions are"
        [[ $hidden_count -eq 1 ]] && plural="action is"
        printf "    \033[33mNote: %d admin-only %s hidden.\033[0m\n" "$hidden_count" "$plural"
        printf "    \033[33m      Re-run with sudo to access them.\033[0m\n"
        echo ""
    fi

    # Show items - hide admin-only items when not root
    if $is_admin || ! $needs_system_store; then
        # Show [1] only if admin, or if it's not needed (non-recommended shown in gray)
        if $is_admin; then
            if $needs_system_store; then
                echo "    [1] Install Zscaler certs to system trust store [recommended]"
            else
                printf "    \033[90m[1] Install Zscaler certs to system trust store\033[0m\n"
            fi
        fi
    fi

    if $needs_bundle; then
        echo "    [2] Write combined CA bundle + set env vars (user scope) [recommended]"
    else
        printf "    \033[90m[2] Write combined CA bundle + set env vars (user scope)\033[0m\n"
    fi

    if $AUDIT_AZURE_CLI_INSTALLED && ($is_admin || ! $needs_az_patch); then
        if $is_admin; then
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

    if $AUDIT_AZURE_CLI_INSTALLED && ($is_admin || ! $needs_pip_certs); then
        if $is_admin; then
            if $needs_pip_certs; then
                echo "    [6] Install pip-system-certs in Azure CLI Python [recommended]"
            else
                printf "    \033[90m[6] Install pip-system-certs in Azure CLI Python\033[0m\n"
            fi
        fi
    fi

    if command_exists keytool && [[ -n "${JAVA_HOME:-}" ]]; then
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

    ! $AUDIT_SYSTEM_STORE_OK && needs_system_store=true
    [[ "$AUDIT_ENV_VARS_STATE" != "ok" ]] || ! $AUDIT_COMBINED_BUNDLE_OK && needs_bundle=true
    $AUDIT_AZURE_CLI_INSTALLED && ! $AUDIT_AZURE_CLI_BUNDLE_OK && needs_az_patch=true
    command_exists git && ! $AUDIT_GIT_CONFIGURED && needs_git=true
    command_exists npm && ! $AUDIT_NPM_CONFIGURED && needs_npm=true
    $AUDIT_AZURE_CLI_INSTALLED && ! $AUDIT_PIP_SYSTEM_CERTS_OK && needs_pip_certs=true
    command_exists keytool && [[ -n "${JAVA_HOME:-}" ]] && ! $AUDIT_JAVA_CONFIGURED && needs_java=true

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
                elif ! $is_admin; then
                    write_status FAIL "Option [3] requires root. Re-run with sudo."
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
                elif ! $is_admin; then
                    write_status FAIL "Option [6] requires root. Re-run with sudo."
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
            A)
                local has_recommended=false
                ($needs_system_store || $needs_bundle || $needs_az_patch || $needs_git || $needs_npm || $needs_pip_certs || $needs_java) && has_recommended=true

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

                if $needs_az_patch && $is_admin; then
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

                if $needs_pip_certs && $is_admin; then
                    if install_pip_system_certs "$AUDIT_AZURE_CLI_PYTHON"; then
                        needs_pip_certs=false; AUDIT_PIP_SYSTEM_CERTS_OK=true
                    fi
                fi

                if $needs_java && $is_admin; then
                    if configure_java_keystore "$AUDIT_ZSCALER_PEM"; then
                        needs_java=false; AUDIT_JAVA_CONFIGURED=true
                    fi
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
    if [[ "$SCOPE" == "system" ]] && ! is_root; then
        echo "Error: --scope system requires root." >&2
        exit 1
    fi
    if $PATCH_AZURE_CLI && ! is_root; then
        echo "Error: --patch-azure-cli may require root." >&2
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

    write_section "Done"
    echo "Restart any open shells and terminals to pick up the new env vars."
    echo "Verify with: $0 --audit --test-connection"
}

# ============================================================================
# Usage
# ============================================================================

show_usage() {
    cat << 'USAGE'
Usage: install-zscaler-trust.sh [OPTIONS]

Audit and install Zscaler certificate trust for CLI tools on Linux
(RHEL/CentOS/Fedora and Debian/Ubuntu).

Modes (mutually exclusive):
  --audit              Audit only, no changes
  --install            Non-interactive install (write bundle + set env vars)
  --rollback           Detect and undo all script-managed changes
  (no flag)            Default: audit + interactive menu

Options:
  --cert-file FILE     PEM file containing Zscaler cert(s) to import
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
  --force              With --rollback: skip the y/N confirmation prompt
  --scope user|system  Env var scope (default: user). System requires root.
  --shell bash|zsh|both  Target shell profile (default: auto-detect)
  -h, --help           Show this help

Examples:
  ./install-zscaler-trust.sh                                    # audit + menu
  ./install-zscaler-trust.sh --audit                            # audit only
  ./install-zscaler-trust.sh --audit --test-connection          # audit + TLS test
  ./install-zscaler-trust.sh --install --cert-file zscaler.pem  # non-interactive
  ./install-zscaler-trust.sh --install --scope system           # system-wide (root)
  ./install-zscaler-trust.sh --rollback                         # interactive rollback
  ./install-zscaler-trust.sh --rollback --force                 # rollback without prompt
  ./install-zscaler-trust.sh --cert-url https://it.corp.example.com/root.cer
  ./install-zscaler-trust.sh --cert-url https://proxy.corp.example.com \
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
    detect_distro

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
