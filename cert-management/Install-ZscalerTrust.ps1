<#
.SYNOPSIS
    Audit and install Zscaler certificate trust for Python/Node/CLI tooling
    that doesn't honor the Windows trust store.

.DESCRIPTION
    Default behavior (no flags): runs the read-only audit, then presents an
    interactive menu of recommended next steps based on what was found.

    -Audit:    audit only, no interactive menu (use for CI / automation)
    -Install:  run the standard install non-interactively (write bundle + set
               env vars; add -PatchAzureCli for the cacert.pem patch)

.PARAMETER Audit
    Run the audit only. No menu, no changes.

.PARAMETER Install
    Run the install non-interactively, skipping the audit and menu.

.PARAMETER Rollback
    Detect and undo everything this script could have applied: bundle files,
    env vars (User and Machine where the value points at our bundle), Azure
    CLI cacert.pem patch, pip-system-certs install. Asks for confirmation
    unless -Force is also given. Skips admin-required steps when not elevated.

.PARAMETER Force
    Only with -Rollback. Skip the y/N confirmation prompt.

.PARAMETER TestConnection
    Include a live TLS handshake to login.microsoftonline.com (or -TestHost)
    in the audit output.

.PARAMETER TestHost
    Hostname for -TestConnection. Default: login.microsoftonline.com.

.PARAMETER BundleDir
    Output directory for generated PEM files. Default: $env:USERPROFILE\certs

.PARAMETER PatchAzureCli
    Only with -Install. Append Zscaler certs to Azure CLI's certifi bundle.
    Requires admin.

.PARAMETER Scope
    Only with -Install. 'User' or 'Machine' env var persistence.
    Machine requires admin. Default: User.

.PARAMETER CertUrls
    Optional list of URLs to fetch additional certificates from. Two strategies
    are auto-selected based on URL shape:

      - URLs ending in .cer/.crt/.pem/.der are downloaded over HTTP(S) and
        parsed as DER (binary) or PEM (text). Useful for IT-published cert
        files, e.g. https://it.corp.example.com/proxy-root.cer

      - All other https:// URLs trigger a TLS handshake, and the CA portion of
        the presented chain (everything except the server leaf) is captured.
        Useful for snagging an intercepting proxy CA from any reachable host.

    Certs from URLs are deduplicated by thumbprint against each other and
    against Windows-store-discovered certs, then added to the trust set used
    by the audit and install actions.

.PARAMETER CertUrlTimeoutSec
    Per-URL timeout for downloads and TLS handshakes. Default: 10.

.EXAMPLE
    .\Install-ZscalerTrust.ps1                                  # audit + menu
    .\Install-ZscalerTrust.ps1 -TestConnection                  # audit + TLS + menu
    .\Install-ZscalerTrust.ps1 -Audit                           # audit only
    .\Install-ZscalerTrust.ps1 -Install -PatchAzureCli          # legacy non-interactive
    .\Install-ZscalerTrust.ps1 -Rollback                        # interactive rollback
    .\Install-ZscalerTrust.ps1 -Rollback -Force                 # rollback without prompt
    .\Install-ZscalerTrust.ps1 -CertUrls 'https://it.corp.example.com/root.cer'
    .\Install-ZscalerTrust.ps1 -CertUrls @(
        'https://it.corp.example.com/root.cer',
        'https://internal-app.corp.example.com'
    )
#>

[CmdletBinding()]
param(
    [switch]$Audit,
    [switch]$Install,
    [switch]$Rollback,
    [switch]$Force,
    [switch]$TestConnection,
    [string]$TestHost = 'login.microsoftonline.com',
    [string]$BundleDir = (Join-Path $env:USERPROFILE 'certs'),
    [switch]$PatchAzureCli,
    [ValidateSet('User', 'Machine')]
    [string]$Scope = 'User',
    [string[]]$CertUrls = @(),
    [int]$CertUrlTimeoutSec = 10
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# Helpers
# ============================================================================

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-Pem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $b64 = [Convert]::ToBase64String($Cert.RawData)
    $sb  = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('-----BEGIN CERTIFICATE-----')
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $len = [Math]::Min(64, $b64.Length - $i)
        [void]$sb.AppendLine($b64.Substring($i, $len))
    }
    [void]$sb.Append('-----END CERTIFICATE-----')
    $sb.ToString()
}

function Write-Status {
    param(
        [ValidateSet('OK', 'FAIL', 'WARN', 'INFO')]
        [string]$Level,
        [string]$Message
    )
    $map = @{
        OK   = @{ Symbol = '[+]'; Color = 'Green'  }
        FAIL = @{ Symbol = '[-]'; Color = 'Red'    }
        WARN = @{ Symbol = '[!]'; Color = 'Yellow' }
        INFO = @{ Symbol = '[ ]'; Color = 'Gray'   }
    }
    $entry = $map[$Level]
    Write-Host "    $($entry.Symbol) " -ForegroundColor $entry.Color -NoNewline
    Write-Host $Message
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Find-ZscalerCerts {
    $stores = @(
        'Cert:\LocalMachine\Root',
        'Cert:\LocalMachine\CA',
        'Cert:\LocalMachine\AuthRoot',
        'Cert:\CurrentUser\Root',
        'Cert:\CurrentUser\CA'
    )
    $found = foreach ($s in $stores) {
        if (Test-Path $s) {
            Get-ChildItem $s -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -match 'Zscaler' -or $_.Issuer -match 'Zscaler' } |
                ForEach-Object {
                    Add-Member -InputObject $_ -NotePropertyName 'StorePath' `
                        -NotePropertyValue $s -PassThru -Force
                }
        }
    }
    $found | Sort-Object Thumbprint -Unique
}

function Get-CertCN {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    ($Cert.Subject -split ',')[0].Trim() -replace '^CN=', ''
}

function Test-BundleHasCerts {
    param(
        [string]$BundlePath,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs
    )
    $result = @{ Found = @(); Missing = @() }
    if (-not (Test-Path $BundlePath)) { return $null }
    try {
        $stripped = (Get-Content $BundlePath -Raw -ErrorAction Stop) -replace '\s', ''
    } catch {
        return $null
    }
    foreach ($c in $Certs) {
        $b64 = [Convert]::ToBase64String($c.RawData)
        $cn  = Get-CertCN $c
        if ($stripped.Contains($b64)) { $result.Found += $cn }
        else                          { $result.Missing += $cn }
    }
    $result
}

function Get-AzureCliPython {
    @(
        'C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe',
        'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\python.exe'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function Get-AzureCliBundle {
    @(
        'C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages\certifi\cacert.pem',
        'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\Lib\site-packages\certifi\cacert.pem'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function Get-PythonInterpreters {
    $list = @()
    $azPy = Get-AzureCliPython
    if ($azPy) { $list += [pscustomobject]@{ Label = 'Azure CLI Python'; Path = $azPy } }

    $sysPy = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($sysPy -and $sysPy -ne $azPy) {
        $list += [pscustomobject]@{ Label = 'python (PATH)'; Path = $sysPy }
    }

    $pyLauncher = (Get-Command py -ErrorAction SilentlyContinue).Source
    if ($pyLauncher) {
        try {
            $resolved = & $pyLauncher -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $resolved) {
                $rp = $resolved.Trim()
                if ($rp -ne $sysPy -and $rp -ne $azPy) {
                    $list += [pscustomobject]@{ Label = 'py launcher default'; Path = $rp }
                }
            }
        } catch { }
    }
    $list
}

function Get-CertifiPath {
    param([string]$PythonExe)
    try {
        $out = & $PythonExe -c "import certifi; print(certifi.where())" 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return $out.Trim() }
    } catch { }
    return $null
}

function Test-PipPackage {
    param([string]$PythonExe, [string]$Package)
    try {
        & $PythonExe -m pip show $Package 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-IsScriptBundle {
    <#
        Heuristic: does this path look like a bundle this script created?
        Matches our specific filenames; checked when deciding which env vars
        are safe to unset during rollback.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $name = Split-Path $Path -Leaf
    return ($name -eq 'combined-ca-bundle.pem' -or $name -eq 'zscaler-certs.pem')
}

function ConvertFrom-PemBlocks {
    <#
        Parse one or more PEM CERTIFICATE blocks out of a string and return
        X509Certificate2 objects. Tolerates extra whitespace and surrounding text.
    #>
    param([string]$PemText)
    $certs = @()
    $pattern = '(?ms)-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----'
    $blocks = [regex]::Matches($PemText, $pattern)
    foreach ($m in $blocks) {
        $b64 = $m.Groups[1].Value -replace '\s', ''
        try {
            $bytes = [Convert]::FromBase64String($b64)
            $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)
        } catch {
            Write-Warning "Failed to decode PEM block: $($_.Exception.Message)"
        }
    }
    , $certs
}

function Get-CertsFromUrl {
    <#
        Retrieves certificates from a URL using one of two strategies:

        1. URL path ends in .cer/.crt/.pem/.der  -> HTTP download. Auto-detects
           DER (binary) vs PEM (text) by trying DER first and falling back.

        2. Otherwise, https://host[:port]        -> TLS handshake. Captures the
           full certificate chain and returns the CA elements (everything
           except the server leaf at index 0).

        Returns @() on failure (with a status line printed). Each returned cert
        is annotated with a 'SourceUrl' property for downstream display.
    #>
    param(
        [string]$Url,
        [int]$TimeoutSec = 10
    )

    $certs = @()
    $uri = [Uri]$Url
    $isCertFile = $uri.AbsolutePath -match '\.(cer|crt|pem|der)$'

    if ($isCertFile) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
            $content = $resp.Content
            if ($content -is [byte[]]) {
                # Try DER first, fall back to PEM
                $parsed = $null
                try {
                    $parsed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$content)
                } catch { }
                if ($parsed) {
                    $certs += $parsed
                } else {
                    $text = [System.Text.Encoding]::UTF8.GetString($content)
                    $certs += ConvertFrom-PemBlocks $text
                }
            } else {
                $certs += ConvertFrom-PemBlocks ([string]$content)
            }
        } catch {
            Write-Status FAIL "Download failed: $Url"
            Write-Host "        $($_.Exception.Message)"
            return , @()
        }
    }
    elseif ($uri.Scheme -in 'https', 'http') {
        $hostname = $uri.Host
        $port = if ($uri.Port -gt 0) { $uri.Port } else { 443 }
        $tcp = $null; $ssl = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ReceiveTimeout = $TimeoutSec * 1000
            $tcp.SendTimeout    = $TimeoutSec * 1000
            $tcp.Connect($hostname, $port)
            $script:capturedChain = $null
            $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
                param($s, $cert, $chain, $errors)
                $script:capturedChain = $chain
                return $true
            }
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
            $ssl.AuthenticateAsClient($hostname)
            if ($script:capturedChain) {
                # Skip [0] (server leaf), take CA elements
                for ($i = 1; $i -lt $script:capturedChain.ChainElements.Count; $i++) {
                    $certs += $script:capturedChain.ChainElements[$i].Certificate
                }
            }
        } catch {
            Write-Status FAIL "TLS handshake failed: $Url"
            Write-Host "        $($_.Exception.Message)"
            return , @()
        } finally {
            if ($ssl) { $ssl.Dispose() }
            if ($tcp) { $tcp.Dispose() }
        }
    }
    else {
        Write-Status WARN "Unsupported URL scheme '$($uri.Scheme)' for $Url"
        return , @()
    }

    foreach ($c in $certs) {
        Add-Member -InputObject $c -NotePropertyName SourceUrl -NotePropertyValue $Url -Force
    }
    , $certs
}

function Get-CertsFromUrls {
    <#
        Iterate a list of URLs, fetch certs from each, deduplicate by thumbprint
        across all sources (and against an optional set already discovered).
    #>
    param(
        [string[]]$Urls,
        [int]$TimeoutSec,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$AlreadyHave = @()
    )
    $seen = @{}
    foreach ($c in $AlreadyHave) { $seen[$c.Thumbprint] = $true }

    $out = @()
    foreach ($url in $Urls) {
        if ([string]::IsNullOrWhiteSpace($url)) { continue }
        Write-Host "    Fetching: $url" -ForegroundColor Gray
        $fetched = Get-CertsFromUrl -Url $url -TimeoutSec $TimeoutSec
        foreach ($c in $fetched) {
            if (-not $seen.ContainsKey($c.Thumbprint)) {
                $seen[$c.Thumbprint] = $true
                $out += $c
            }
        }
    }
    , $out
}

# ============================================================================
# Audit
# ============================================================================

function Invoke-Audit {
    <#
        Returns a result object:
            HasCerts            : bool   (any managed certs at all?)
            ManagedCerts        : X509Certificate2[]  (Zscaler + URL-fetched, deduped)
            ZscalerCerts        : X509Certificate2[]  (from Windows store only)
            UrlCerts            : X509Certificate2[]  (from -CertUrls only)
            AzureCliInstalled   : bool
            AzureCliBundleOk    : bool
            AzureCliPython      : string|null
            PipSystemCertsOk    : bool
            EnvVarsState        : 'ok'|'broken'|'none-set'
            CombinedBundleOk    : bool
    #>
    param(
        [switch]$RunTlsTest,
        [string]$TlsHost,
        [string[]]$Urls = @(),
        [int]$UrlTimeoutSec = 10
    )

    Write-Host ""
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "  Zscaler Trust Audit" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan

    $result = [pscustomobject]@{
        HasCerts          = $false
        ManagedCerts      = @()
        ZscalerCerts      = @()
        UrlCerts          = @()
        AzureCliInstalled = $false
        AzureCliBundleOk  = $false
        AzureCliPython    = $null
        PipSystemCertsOk  = $false
        EnvVarsState      = 'none-set'
        CombinedBundleOk  = $false
    }

    # ---- 1. Trusted certificates (Windows stores + URL sources) ----
    Write-Section "[1] Trusted Certificates"
    $zscalerCerts = Find-ZscalerCerts
    if ($zscalerCerts) {
        Write-Host "    From Windows certificate stores:" -ForegroundColor DarkGray
        foreach ($c in $zscalerCerts) {
            $cn      = Get-CertCN $c
            $store   = $c.StorePath -replace '^Cert:\\', ''
            $expires = $c.NotAfter.ToString('yyyy-MM-dd')
            $expSoon = ($c.NotAfter - (Get-Date)).TotalDays -lt 90
            Write-Status OK "$cn"
            Write-Host "        Source:     Windows store ($store)"
            Write-Host "        Expires:    $expires$(if ($expSoon) { '  <-- expires within 90 days!' })"
            Write-Host "        Thumbprint: $($c.Thumbprint)"
        }
    } else {
        Write-Status INFO "No Zscaler certs found in Windows certificate stores"
    }

    $urlCerts = @()
    if ($Urls -and $Urls.Count -gt 0) {
        Write-Host ""
        Write-Host "    From -CertUrls sources:" -ForegroundColor DarkGray
        $urlCerts = Get-CertsFromUrls -Urls $Urls -TimeoutSec $UrlTimeoutSec -AlreadyHave $zscalerCerts
        if ($urlCerts.Count -eq 0) {
            Write-Status INFO "No new certificates retrieved from URLs (all duplicates of Windows-store certs, or fetches failed)"
        } else {
            foreach ($c in $urlCerts) {
                $cn      = Get-CertCN $c
                $expires = $c.NotAfter.ToString('yyyy-MM-dd')
                $expSoon = ($c.NotAfter - (Get-Date)).TotalDays -lt 90
                $src     = if ($c.PSObject.Properties['SourceUrl']) { $c.SourceUrl } else { '<unknown>' }
                Write-Status OK "$cn"
                Write-Host "        Source:     URL ($src)"
                Write-Host "        Expires:    $expires$(if ($expSoon) { '  <-- expires within 90 days!' })"
                Write-Host "        Thumbprint: $($c.Thumbprint)"
            }
        }
    }

    $managedCerts = @()
    $managedCerts += $zscalerCerts
    $managedCerts += $urlCerts

    if ($managedCerts.Count -eq 0) {
        Write-Host ""
        Write-Status FAIL "No managed certificates discovered from any source"
        Write-Host "        Nothing to wire up. If you expected Zscaler to be installed,"
        Write-Host "        contact your IT/security team about GPO/MDM cert distribution."
        Write-Host "        You can also pass -CertUrls to retrieve certs from URLs."
        return $result
    }

    $result.HasCerts     = $true
    $result.ZscalerCerts = $zscalerCerts
    $result.UrlCerts     = $urlCerts
    $result.ManagedCerts = $managedCerts

    # ---- 2. CA bundle files ----
    Write-Section "[2] CA Bundle Files"
    $candidateBundles = @()

    $azBundle = Get-AzureCliBundle
    $result.AzureCliPython = Get-AzureCliPython
    $result.AzureCliInstalled = [bool]$azBundle
    if ($azBundle) {
        $candidateBundles += [pscustomobject]@{ Label = 'Azure CLI certifi'; Path = $azBundle; Tag = 'azurecli' }
    }

    foreach ($py in (Get-PythonInterpreters)) {
        if ($py.Path -eq $result.AzureCliPython) { continue }
        $cert = Get-CertifiPath $py.Path
        if ($cert -and -not ($candidateBundles.Path -contains $cert)) {
            $candidateBundles += [pscustomobject]@{ Label = "$($py.Label) certifi"; Path = $cert; Tag = 'python' }
        }
    }

    $combined = Join-Path $BundleDir 'combined-ca-bundle.pem'
    if (Test-Path $combined) {
        $candidateBundles += [pscustomobject]@{
            Label = 'Combined CA bundle (this script)'
            Path  = $combined
            Tag   = 'combined'
        }
    }

    if (-not $candidateBundles) {
        Write-Status INFO "No CA bundle files discovered"
    }

    foreach ($b in $candidateBundles) {
        $r = Test-BundleHasCerts -BundlePath $b.Path -Certs $managedCerts
        $stateOk = ($r -and $r.Missing.Count -eq 0)
        if ($null -eq $r) {
            Write-Status FAIL "$($b.Label): cannot read"
        } elseif ($stateOk) {
            Write-Status OK "$($b.Label)"
            Write-Host "        Path: $($b.Path)"
            Write-Host "        Contains all $($r.Found.Count) managed cert(s)"
        } elseif ($r.Found.Count -gt 0) {
            Write-Status WARN "$($b.Label) - partial"
            Write-Host "        Path: $($b.Path)"
            Write-Host "        Missing: $($r.Missing -join ', ')"
        } else {
            Write-Status FAIL "$($b.Label) - no managed certs"
            Write-Host "        Path: $($b.Path)"
        }
        if ($b.Tag -eq 'azurecli')  { $result.AzureCliBundleOk = $stateOk }
        if ($b.Tag -eq 'combined')  { $result.CombinedBundleOk = $stateOk }
    }

    # ---- 3. Environment variables ----
    Write-Section "[3] Environment Variables"
    $varNames = @('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'PIP_CERT')
    $envOk = $true
    $anyEnvSet = $false

    foreach ($scopeName in @('User', 'Machine')) {
        Write-Host ""
        Write-Host "    $scopeName scope:" -ForegroundColor DarkGray
        foreach ($var in $varNames) {
            $val = [Environment]::GetEnvironmentVariable($var, $scopeName)
            if (-not $val) {
                Write-Host "        [ ] $var = (not set)" -ForegroundColor DarkGray
                continue
            }
            $anyEnvSet = $true
            if (-not (Test-Path $val)) {
                Write-Status FAIL "$var = $val (file does not exist)"
                $envOk = $false; continue
            }
            $r = Test-BundleHasCerts -BundlePath $val -Certs $managedCerts
            if ($null -eq $r -or $r.Missing.Count -gt 0) {
                Write-Status WARN "$var = $val"
                if ($r) { Write-Host "        Missing: $($r.Missing -join ', ')" }
                $envOk = $false
            } else {
                Write-Status OK "$var = $val"
            }
        }
    }

    Write-Host ""
    foreach ($scopeName in @('User', 'Machine', 'Process')) {
        $disable = [Environment]::GetEnvironmentVariable('AZURE_CLI_DISABLE_CONNECTION_VERIFICATION', $scopeName)
        if ($disable) {
            Write-Status WARN "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=$disable ($scopeName scope) - SSL verification DISABLED"
        }
    }
    $result.EnvVarsState = if (-not $anyEnvSet) { 'none-set' } elseif ($envOk) { 'ok' } else { 'broken' }

    # ---- 4. Python trust-store bridges ----
    Write-Section "[4] Python Trust-Store Bridges (pip-system-certs)"
    $pyInterps = Get-PythonInterpreters
    if (-not $pyInterps) {
        Write-Status INFO "No Python interpreters discovered"
    } else {
        foreach ($py in $pyInterps) {
            $installed = Test-PipPackage -PythonExe $py.Path -Package 'pip-system-certs'
            if ($installed) {
                Write-Status OK "$($py.Label): pip-system-certs installed"
                Write-Host "        Path: $($py.Path)"
            } else {
                Write-Status INFO "$($py.Label): pip-system-certs not installed"
                Write-Host "        Path: $($py.Path)"
            }
            if ($py.Path -eq $result.AzureCliPython) { $result.PipSystemCertsOk = $installed }
        }
        if ($urlCerts.Count -gt 0) {
            Write-Host ""
            Write-Status WARN "pip-system-certs reads only the Windows trust store"
            Write-Host "        URL-sourced certs are NOT picked up by pip-system-certs."
            Write-Host "        Use the bundle/env-var route or import URL certs into the"
            Write-Host "        Windows store first if you need pip-system-certs to see them."
        }
    }

    # ---- 5. Live TLS test ----
    if ($RunTlsTest) {
        Write-Section "[5] Live TLS Test"
        Test-TlsHandshake -Hostname $TlsHost
    }

    return $result
}

function Test-TlsHandshake {
    param([string]$Hostname, [int]$Port = 443)

    Write-Host "    Target: $Hostname`:$Port"
    $tcp = $null; $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ReceiveTimeout = 5000; $tcp.SendTimeout = 5000
        $tcp.Connect($Hostname, $Port)

        $script:capturedChain = $null; $script:capturedErrors = $null
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($s, $cert, $chain, $errors)
            $script:capturedChain  = $chain
            $script:capturedErrors = $errors
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient($Hostname)

        Write-Host "    TLS:        $($ssl.SslProtocol)  /  $($ssl.CipherAlgorithm) $($ssl.CipherStrength)-bit"
        Write-Host "    Chain (as presented by server):"
        if (-not $script:capturedChain) {
            Write-Status WARN "Chain capture failed"; return
        }
        $chainHasZscaler = $false
        for ($i = 0; $i -lt $script:capturedChain.ChainElements.Count; $i++) {
            $el = $script:capturedChain.ChainElements[$i]
            $subj = Get-CertCN $el.Certificate
            $iss  = ($el.Certificate.Issuer -split ',')[0].Trim() -replace '^CN=', ''
            if ($el.Certificate.Subject -match 'Zscaler' -or $el.Certificate.Issuer -match 'Zscaler') {
                $chainHasZscaler = $true
            }
            Write-Host "      [$i] $subj"
            Write-Host "          Issuer:     $iss"
            Write-Host "          Thumbprint: $($el.Certificate.Thumbprint)"
        }
        Write-Host ""
        if ($script:capturedErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
            Write-Status OK "Windows trust store validates this chain"
        } else {
            Write-Status WARN "Policy errors: $($script:capturedErrors)"
        }
        if ($chainHasZscaler) {
            Write-Status INFO "Zscaler IS intercepting this connection"
        } else {
            Write-Status INFO "Zscaler is NOT in the chain for this host"
        }
    } catch {
        Write-Status FAIL "TLS handshake failed: $($_.Exception.Message)"
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

# ============================================================================
# Action functions
# ============================================================================

function Invoke-WriteBundles {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs)

    if (-not (Test-Path $BundleDir)) {
        New-Item -ItemType Directory -Path $BundleDir -Force | Out-Null
    }
    $zscalerPem  = Join-Path $BundleDir 'zscaler-certs.pem'
    $combinedPem = Join-Path $BundleDir 'combined-ca-bundle.pem'

    Write-Section "Writing Zscaler PEM"
    $blocks = $Certs | ForEach-Object { ConvertTo-Pem $_ }
    $blocks -join "`r`n" | Set-Content -Path $zscalerPem -Encoding Ascii
    Write-Host "  $zscalerPem" -ForegroundColor Green

    Write-Section "Building combined CA bundle"
    $basePath = $null
    $candidates = @(
        'C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages\certifi\cacert.pem',
        'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\Lib\site-packages\certifi\cacert.pem'
    )
    $pyExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($pyExe) {
        $detected = Get-CertifiPath $pyExe
        if ($detected) { $candidates += $detected }
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { $basePath = $c; break }
    }
    if ($basePath) {
        Write-Host "  base: $basePath"
        Copy-Item -Path $basePath -Destination $combinedPem -Force
    } else {
        Write-Warning "  No certifi bundle found. Falling back to Windows root store."
        $roots = Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue
        ($roots | ForEach-Object { ConvertTo-Pem $_ }) -join "`r`n" |
            Set-Content -Path $combinedPem -Encoding Ascii
    }
    Add-Content -Path $combinedPem -Value "`r`n# --- Zscaler certificates appended by Install-ZscalerTrust.ps1 ---"
    Add-Content -Path $combinedPem -Value ($blocks -join "`r`n")
    Write-Host "  $combinedPem" -ForegroundColor Green
    return $combinedPem
}

function Invoke-SetEnvVars {
    param([string]$BundlePath, [string]$EnvScope = 'User')

    if ($EnvScope -eq 'Machine' -and -not (Test-IsAdmin)) {
        Write-Status FAIL "Machine scope requires admin. Skipping."
        return $false
    }

    Write-Section "Setting environment variables ($EnvScope scope)"
    $vars = [ordered]@{
        REQUESTS_CA_BUNDLE   = $BundlePath
        SSL_CERT_FILE        = $BundlePath
        CURL_CA_BUNDLE       = $BundlePath
        NODE_EXTRA_CA_CERTS  = $BundlePath
        PIP_CERT             = $BundlePath
    }
    foreach ($kvp in $vars.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($kvp.Key, $kvp.Value, $EnvScope)
        Write-Host ("  {0,-22} = {1}" -f $kvp.Key, $kvp.Value)
    }
    $disable = [Environment]::GetEnvironmentVariable('AZURE_CLI_DISABLE_CONNECTION_VERIFICATION', $EnvScope)
    if ($disable) {
        Write-Warning "Clearing AZURE_CLI_DISABLE_CONNECTION_VERIFICATION (was '$disable')"
        [Environment]::SetEnvironmentVariable('AZURE_CLI_DISABLE_CONNECTION_VERIFICATION', $null, $EnvScope)
    }
    return $true
}

function Invoke-PatchAzureCliBundle {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs)

    if (-not (Test-IsAdmin)) {
        Write-Status FAIL "Patching Program Files requires admin. Skipping."
        return $false
    }
    $azBundle = Get-AzureCliBundle
    if (-not $azBundle) {
        Write-Status WARN "Azure CLI bundle not found. Skipping."
        return $false
    }

    Write-Section "Patching Azure CLI's certifi bundle"
    $azMarker = "# Zscaler-appended-by-Install-ZscalerTrust"
    $existing = Get-Content $azBundle -Raw
    if ($existing -match [regex]::Escape($azMarker)) {
        Write-Host "  Already patched (marker present). Skipping." -ForegroundColor Yellow
        return $true
    }
    $backup = "$azBundle.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $azBundle $backup
    $blocks = $Certs | ForEach-Object { ConvertTo-Pem $_ }
    Add-Content -Path $azBundle -Value "`r`n$azMarker"
    Add-Content -Path $azBundle -Value ($blocks -join "`r`n")
    Write-Host "  Patched. Backup: $backup" -ForegroundColor Green
    return $true
}

function Invoke-InstallPipSystemCerts {
    param([string]$PythonExe)

    if (-not (Test-IsAdmin)) {
        Write-Status FAIL "Modifying Azure CLI's Python install requires admin. Skipping."
        return $false
    }
    if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
        Write-Status WARN "Azure CLI Python not found. Skipping."
        return $false
    }

    Write-Section "Installing pip-system-certs in $PythonExe"
    & $PythonExe -m pip install pip-system-certs
    if ($LASTEXITCODE -eq 0) {
        Write-Status OK "Installed. Azure CLI Python now reads the Windows trust store directly."
        return $true
    } else {
        Write-Status FAIL "pip install failed (exit $LASTEXITCODE)"
        return $false
    }
}

# ============================================================================
# Rollback
# ============================================================================

function Invoke-RollbackAll {
    <#
        Detects everything this script could have applied, presents a plan,
        prompts for confirmation, and unwinds it. Skips admin-required steps
        when not elevated rather than failing the whole rollback.
    #>
    param([switch]$NoConfirm)

    $isAdmin = Test-IsAdmin
    $plan = @()

    # ---- bundle files ----
    $zscalerPem  = Join-Path $BundleDir 'zscaler-certs.pem'
    $combinedPem = Join-Path $BundleDir 'combined-ca-bundle.pem'
    foreach ($file in @($zscalerPem, $combinedPem)) {
        if (Test-Path $file) {
            $plan += [pscustomobject]@{
                Kind       = 'DeleteFile'
                Label      = "Delete bundle file"
                Target     = $file
                NeedsAdmin = $false
            }
        }
    }

    # ---- env vars (User + Machine) where value points at our bundle ----
    $varNames = @('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'PIP_CERT')
    foreach ($scopeName in @('User', 'Machine')) {
        foreach ($var in $varNames) {
            $val = [Environment]::GetEnvironmentVariable($var, $scopeName)
            if ($val -and (Test-IsScriptBundle $val)) {
                $plan += [pscustomobject]@{
                    Kind       = 'UnsetEnv'
                    Label      = "Unset env var ($scopeName)"
                    Target     = "$var = $val"
                    NeedsAdmin = ($scopeName -eq 'Machine')
                    EnvVar     = $var
                    EnvScope   = $scopeName
                }
            }
        }
    }

    # ---- AZURE_CLI_DISABLE_CONNECTION_VERIFICATION (cleanup) ----
    foreach ($scopeName in @('User', 'Machine')) {
        $val = [Environment]::GetEnvironmentVariable('AZURE_CLI_DISABLE_CONNECTION_VERIFICATION', $scopeName)
        if ($val) {
            $plan += [pscustomobject]@{
                Kind       = 'UnsetEnv'
                Label      = "Unset insecure opt-out ($scopeName)"
                Target     = "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION = $val"
                NeedsAdmin = ($scopeName -eq 'Machine')
                EnvVar     = 'AZURE_CLI_DISABLE_CONNECTION_VERIFICATION'
                EnvScope   = $scopeName
            }
        }
    }

    # ---- Azure CLI cacert.pem patch ----
    $azBundle = Get-AzureCliBundle
    if ($azBundle) {
        try {
            $azContent = Get-Content $azBundle -Raw -ErrorAction Stop
            if ($azContent -match 'Zscaler-appended-by-Install-ZscalerTrust') {
                $plan += [pscustomobject]@{
                    Kind       = 'UnpatchAzureCli'
                    Label      = 'Remove appended block from Azure CLI cacert.pem'
                    Target     = $azBundle
                    NeedsAdmin = $true
                }
            }
        } catch {
            # unreadable; skip
        }
    }

    # ---- pip-system-certs in Azure CLI Python ----
    $azPy = Get-AzureCliPython
    if ($azPy -and (Test-PipPackage -PythonExe $azPy -Package 'pip-system-certs')) {
        $plan += [pscustomobject]@{
            Kind       = 'UninstallPipSystemCerts'
            Label      = 'Uninstall pip-system-certs from Azure CLI Python'
            Target     = $azPy
            NeedsAdmin = $true
        }
    }

    # ---- present plan ----
    Write-Section "Rollback Plan"
    if ($plan.Count -eq 0) {
        Write-Status OK "Nothing to roll back. Trust setup is already clean."
        return
    }

    foreach ($p in $plan) {
        $tag = ''
        if ($p.NeedsAdmin -and -not $isAdmin) { $tag = '   [needs admin - will skip]' }
        Write-Host "    - $($p.Label)$tag"
        Write-Host "      $($p.Target)" -ForegroundColor DarkGray
    }
    Write-Host ""

    $skipCount = ($plan | Where-Object { $_.NeedsAdmin -and -not $isAdmin }).Count
    if ($skipCount -gt 0) {
        Write-Status WARN "$skipCount step(s) require admin and will be skipped."
        Write-Host "        Re-run elevated to roll back those items."
        Write-Host ""
    }

    # ---- confirm ----
    if (-not $NoConfirm) {
        $resp = (Read-Host "    Proceed with rollback? [y/N]").Trim().ToLower()
        if ($resp -ne 'y' -and $resp -ne 'yes') {
            Write-Host "    Aborted." -ForegroundColor Gray
            return
        }
    }

    # ---- execute ----
    Write-Section "Executing rollback"
    foreach ($p in $plan) {
        if ($p.NeedsAdmin -and -not $isAdmin) {
            Write-Status WARN "Skipped (needs admin): $($p.Label)"
            continue
        }
        try {
            switch ($p.Kind) {
                'DeleteFile' {
                    Remove-Item $p.Target -Force -ErrorAction Stop
                    Write-Status OK "Deleted: $($p.Target)"
                }
                'UnsetEnv' {
                    [Environment]::SetEnvironmentVariable($p.EnvVar, $null, $p.EnvScope)
                    Write-Status OK "Unset: $($p.EnvVar) ($($p.EnvScope))"
                }
                'UnpatchAzureCli' {
                    $content = Get-Content $p.Target -Raw -ErrorAction Stop
                    $marker  = '# Zscaler-appended-by-Install-ZscalerTrust'
                    $idx     = $content.IndexOf($marker)
                    if ($idx -ge 0) {
                        $head = $content.Substring(0, $idx).TrimEnd()
                        # Make a safety backup before truncating
                        $bak = "$($p.Target).rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                        Copy-Item $p.Target $bak
                        Set-Content -Path $p.Target -Value $head -Encoding Ascii -NoNewline
                        # Add a final newline to keep the file POSIX-friendly
                        Add-Content -Path $p.Target -Value ''
                        Write-Status OK "Unpatched: $($p.Target)"
                        Write-Host "        Backup: $bak"
                    } else {
                        Write-Status WARN "Marker not found (already removed?)"
                    }
                }
                'UninstallPipSystemCerts' {
                    & $p.Target -m pip uninstall -y pip-system-certs
                    if ($LASTEXITCODE -eq 0) {
                        Write-Status OK "Uninstalled pip-system-certs"
                    } else {
                        Write-Status FAIL "pip uninstall failed (exit $LASTEXITCODE)"
                    }
                }
                default {
                    Write-Status WARN "Unknown rollback kind: $($p.Kind)"
                }
            }
        } catch {
            Write-Status FAIL "$($p.Label): $($_.Exception.Message)"
        }
    }

    # Optionally remove BundleDir if it's now empty
    if ((Test-Path $BundleDir) -and -not (Get-ChildItem $BundleDir -Force -ErrorAction SilentlyContinue)) {
        try {
            Remove-Item $BundleDir -Force
            Write-Status OK "Removed empty bundle directory: $BundleDir"
        } catch { }
    }

    Write-Section "Rollback complete"
    Write-Host "    Restart open shells / VS Code to clear in-process env vars."
}

# ============================================================================
# Interactive menu
# ============================================================================

function Show-InteractiveMenu {
    param($AuditResult)

    if (-not $AuditResult.HasCerts) {
        Write-Section "No actions available"
        Write-Host "    No Zscaler certs found in the Windows trust store, so there's"
        Write-Host "    nothing to wire up. If you expected Zscaler to be installed,"
        Write-Host "    contact your IT/security team about GPO/MDM cert distribution."
        return
    }

    $isAdmin = Test-IsAdmin

    # Build the action list, contextual to audit findings.
    # Visible = Available AND (this user has the privilege to run it)
    $actions = [ordered]@{}

    $needsBundle = ($AuditResult.EnvVarsState -ne 'ok') -or (-not $AuditResult.CombinedBundleOk)
    $actions['1'] = [pscustomobject]@{
        Label       = 'Install combined CA bundle and set env vars (User scope)'
        Recommended = $needsBundle
        NeedsAdmin  = $false
        Available   = $true
        Run         = {
            $path = Invoke-WriteBundles -Certs $AuditResult.ManagedCerts
            Invoke-SetEnvVars -BundlePath $path -EnvScope 'User' | Out-Null
        }
    }

    $needsPatch = $AuditResult.AzureCliInstalled -and -not $AuditResult.AzureCliBundleOk
    $actions['2'] = [pscustomobject]@{
        Label       = "Patch Azure CLI certifi bundle (fixes 'az login')"
        Recommended = $needsPatch
        NeedsAdmin  = $true
        Available   = $AuditResult.AzureCliInstalled
        Run         = { Invoke-PatchAzureCliBundle -Certs $AuditResult.ManagedCerts | Out-Null }
    }

    $needsPip = $AuditResult.AzureCliInstalled -and -not $AuditResult.PipSystemCertsOk
    $actions['3'] = [pscustomobject]@{
        Label       = 'Install pip-system-certs in Azure CLI Python (best long-term fix)'
        Recommended = $needsPip
        NeedsAdmin  = $true
        Available   = $AuditResult.AzureCliInstalled
        Run         = { Invoke-InstallPipSystemCerts -PythonExe $AuditResult.AzureCliPython | Out-Null }
    }

    $actions['4'] = [pscustomobject]@{
        Label       = "Run live TLS handshake test"
        Recommended = $false
        NeedsAdmin  = $false
        Available   = $true
        Run         = {
            $h = Read-Host "    Hostname [default: $TestHost]"
            if ([string]::IsNullOrWhiteSpace($h)) { $h = $TestHost }
            Write-Host ""
            Test-TlsHandshake -Hostname $h
        }
    }

    $actions['5'] = [pscustomobject]@{
        Label       = 'Roll back all script-managed changes'
        Recommended = $false
        NeedsAdmin  = $false   # detects + skips admin items if not elevated
        Available   = $true
        Run         = { Invoke-RollbackAll }
    }

    # Compute Visible for each action based on current admin context
    foreach ($key in $actions.Keys) {
        $a = $actions[$key]
        $visible = $a.Available -and (-not $a.NeedsAdmin -or $isAdmin)
        Add-Member -InputObject $a -NotePropertyName Visible -NotePropertyValue $visible -Force
    }

    # Count actions hidden purely because of admin (so we can tell the user)
    $hiddenAdminCount = (
        $actions.Values | Where-Object { $_.Available -and $_.NeedsAdmin -and -not $isAdmin }
    ).Count

    Show-MenuOptions -Actions $actions -IsAdmin $isAdmin -HiddenAdminCount $hiddenAdminCount

    # ---- prompt loop ----
    while ($true) {
        $choice = (Read-Host "    Your choice").Trim().ToUpper()
        if (-not $choice) { continue }

        if ($choice -eq 'Q') {
            Write-Host "    Done." -ForegroundColor Gray
            return
        }

        $ranSomething = $false

        if ($choice -eq 'A') {
            $recs = $actions.Values | Where-Object { $_.Recommended -and $_.Visible }
            if (-not $recs) {
                Write-Status WARN "No recommended actions available in this context."
            } else {
                foreach ($a in $recs) { & $a.Run }
                Write-Section "All recommended actions complete"
                Write-Host "    Restart open shells / VS Code to pick up new env vars."
                $ranSomething = $true
            }
        }
        elseif ($actions.Contains($choice)) {
            $a = $actions[$choice]
            if (-not $a.Available) {
                Write-Status WARN "Option [$choice] is not available in this environment."
            } elseif (-not $a.Visible) {
                Write-Status FAIL "Option [$choice] requires admin. Re-run PowerShell as administrator."
            } else {
                & $a.Run
                $ranSomething = $true
            }
        }
        else {
            Write-Status WARN "Invalid choice: $choice"
        }

        if ($ranSomething) {
            # Re-render the menu below the action's output so the user doesn't
            # have to scroll up to see their options again.
            Show-MenuOptions -Actions $actions -IsAdmin $isAdmin -HiddenAdminCount $hiddenAdminCount
        }
    }
}

function Show-MenuOptions {
    <#
        Renders the action menu. Called once after the audit, then again after
        each user action so the menu stays visible without scrolling.
    #>
    param(
        $Actions,
        [bool]$IsAdmin,
        [int]$HiddenAdminCount
    )

    $hasRecommended = @(
        $Actions.Values | Where-Object { $_.Recommended -and $_.Visible }
    ).Count -gt 0

    Write-Section "Suggested Next Steps"

    if (-not $hasRecommended) {
        Write-Host "    No outstanding recommended actions for your current context." -ForegroundColor Green
        Write-Host "    You can still run the TLS test or quit."
    } else {
        Write-Host "    Based on the audit, here's what would help:"
    }
    Write-Host ""

    if (-not $IsAdmin -and $HiddenAdminCount -gt 0) {
        $plural = if ($HiddenAdminCount -eq 1) { 'action is' } else { 'actions are' }
        Write-Host "    Note: $HiddenAdminCount admin-only $plural hidden." -ForegroundColor Yellow
        Write-Host "          Re-run PowerShell as administrator to access them." -ForegroundColor Yellow
        Write-Host ""
    }

    foreach ($key in $Actions.Keys) {
        $a = $Actions[$key]
        if (-not $a.Visible) { continue }
        $tag   = if ($a.Recommended) { '  [recommended]' } else { '' }
        $color = if ($a.Recommended) { 'White' } else { 'Gray' }
        Write-Host "    [$key] $($a.Label)$tag" -ForegroundColor $color
    }
    if ($hasRecommended) {
        Write-Host "    [A] Do all recommended actions" -ForegroundColor White
    }
    Write-Host "    [Q] Quit" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# Non-interactive install (for -Install)
# ============================================================================

function Invoke-Install {
    if ($Scope -eq 'Machine' -and -not (Test-IsAdmin)) {
        throw "Scope 'Machine' requires running as administrator."
    }
    if ($PatchAzureCli -and -not (Test-IsAdmin)) {
        throw "-PatchAzureCli requires running as administrator."
    }

    Write-Section "Searching cert stores for Zscaler certificates"
    $zscalerCerts = Find-ZscalerCerts
    if ($zscalerCerts) {
        Write-Host "Found $($zscalerCerts.Count) Zscaler cert(s) in Windows store" -ForegroundColor Green
    } else {
        Write-Host "No Zscaler certs found in Windows store" -ForegroundColor Yellow
    }

    $urlCerts = @()
    if ($CertUrls -and $CertUrls.Count -gt 0) {
        Write-Section "Fetching certificates from URLs"
        $urlCerts = Get-CertsFromUrls -Urls $CertUrls -TimeoutSec $CertUrlTimeoutSec -AlreadyHave $zscalerCerts
        Write-Host "Retrieved $($urlCerts.Count) cert(s) from URL sources" -ForegroundColor Green
    }

    $managedCerts = @()
    $managedCerts += $zscalerCerts
    $managedCerts += $urlCerts
    if ($managedCerts.Count -eq 0) {
        throw "No certificates available from any source. Aborting."
    }

    $combined = Invoke-WriteBundles -Certs $managedCerts
    Invoke-SetEnvVars -BundlePath $combined -EnvScope $Scope | Out-Null
    if ($PatchAzureCli) {
        Invoke-PatchAzureCliBundle -Certs $managedCerts | Out-Null
    }

    Write-Section "Done"
    Write-Host "Restart any open shells, terminals, and VS Code to pick up the new env vars."
    Write-Host "Verify with: .\Install-ZscalerTrust.ps1 -Audit -TestConnection"
}

# ============================================================================
# Main
# ============================================================================

$modeCount = @($Audit, $Install, $Rollback) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($modeCount -gt 1) {
    throw "Choose at most one of -Audit, -Install, -Rollback."
}

if ($Audit) {
    Invoke-Audit -RunTlsTest:$TestConnection -TlsHost $TestHost `
                 -Urls $CertUrls -UrlTimeoutSec $CertUrlTimeoutSec | Out-Null
} elseif ($Install) {
    Invoke-Install
} elseif ($Rollback) {
    Invoke-RollbackAll -NoConfirm:$Force
} else {
    # Default: audit + interactive menu
    $auditResult = Invoke-Audit -RunTlsTest:$TestConnection -TlsHost $TestHost `
                                -Urls $CertUrls -UrlTimeoutSec $CertUrlTimeoutSec
    Show-InteractiveMenu -AuditResult $auditResult
}