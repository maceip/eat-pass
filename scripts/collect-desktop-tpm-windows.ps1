#Requires -Version 5.1
<#
.SYNOPSIS
  Collect a Windows desktop TPM2 client attestation bundle for eat-pass.

.DESCRIPTION
  Requires tpm2-tools (tpm2-tss) on PATH and a provisioned AK/EK activation flow.
  Emits the same hardened JSON schema as collect-desktop-tpm.sh.
  Policy allowlist uses desktop_build_id_hash(build_digest):
    eat-pass desktop-hash-build C:\path\to\agent.exe

  Required environment:
    BINDING, BUILD_DIGEST
    TPM_AK_CTX, TPM_AK_NAME_FILE, AK_CERT_DER
    EK_CERT_DER, EK_CA_CHAIN_DER
    TPM_CREDENTIAL_ACTIVATION_JSON

.PARAMETER OutFile
  Output path, or "-" to write JSON to stdout (SDK mode).

.EXAMPLE
  $env:BINDING = "<64-hex>"
  $env:BUILD_DIGEST = "<64-hex>"
  $env:TPM_AK_CTX = "ak.ctx"
  $env:TPM_AK_NAME_FILE = "ak.name"
  $env:AK_CERT_DER = "ak.der"
  $env:EK_CERT_DER = "ek.der"
  $env:EK_CA_CHAIN_DER = "ek-intermediate.der;ek-root.der"
  $env:TPM_CREDENTIAL_ACTIVATION_JSON = "activation.json"
  .\collect-desktop-tpm-windows.ps1 -OutFile bundle.json
#>
param(
    [string]$OutFile = "desktop-tpm-bundle.json"
)

$ErrorActionPreference = "Stop"

if (-not $env:BINDING) { throw "set BINDING to 32-byte hex (eat-pass channel binding)" }
if (-not $env:BUILD_DIGEST) { throw "set BUILD_DIGEST to sha256(agent binary) hex" }

$requiredEnv = @(
    "TPM_AK_CTX",
    "TPM_AK_NAME_FILE",
    "AK_CERT_DER",
    "EK_CERT_DER",
    "EK_CA_CHAIN_DER",
    "TPM_CREDENTIAL_ACTIVATION_JSON"
)
foreach ($name in $requiredEnv) {
    if (-not [Environment]::GetEnvironmentVariable($name)) {
        throw "missing $name. The old self-signed-AK-only bundle is intentionally not emitted; provision AK/EK credential activation first."
    }
}

$inputFiles = @(
    $env:TPM_AK_CTX,
    $env:TPM_AK_NAME_FILE,
    $env:AK_CERT_DER,
    $env:EK_CERT_DER,
    $env:TPM_CREDENTIAL_ACTIVATION_JSON
)
$ekChainFiles = $env:EK_CA_CHAIN_DER -split ';' | Where-Object { $_ }
$inputFiles += $ekChainFiles
foreach ($path in $inputFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required TPM provenance file is not readable: $path"
    }
}

$tools = @("tpm2_quote", "tpm2_pcrread")
foreach ($t in $tools) {
    if (-not (Get-Command $t -ErrorAction SilentlyContinue)) {
        throw "missing $t — install tpm2-tools (tpm2-tss) on Windows"
    }
}

$work = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_.FullName }
try {
    $quoteMsg = Join-Path $work "quote.msg"
    $quoteSig = Join-Path $work "quote.sig"
    $pcrs = Join-Path $work "pcr.bin"
    $pcrread = Join-Path $work "pcrread.txt"

    $pcrList = "sha256:0,1,2,3,4,5,6,7,8,9"
    & tpm2_quote -c $env:TPM_AK_CTX -l $pcrList -q $env:BINDING `
        -m $quoteMsg -s $quoteSig -o $pcrs -g sha256 2>$null
    & tpm2_pcrread $pcrList | Set-Content -Path $pcrread -Encoding utf8

    function Hex-File($path) {
        -join ([System.BitConverter]::ToString([IO.File]::ReadAllBytes($path)).Replace("-", "").ToLower())
    }

    function Read-EkChain($paths) {
        $out = @()
        foreach ($path in $paths) {
            $out += (Hex-File $path)
        }
        return $out
    }

    function Read-Pcrs($path) {
        $out = @()
        foreach ($line in Get-Content -Path $path) {
            if ($line -match '^\s*(\d+)\s*:\s*0x([0-9A-Fa-f]+)\s*$') {
                $out += [ordered]@{
                    index = [int]$Matches[1]
                    value = $Matches[2].ToLowerInvariant()
                }
            }
        }
        return $out
    }

    $activation = Get-Content -Path $env:TPM_CREDENTIAL_ACTIVATION_JSON -Raw | ConvertFrom-Json
    $data = [ordered]@{
        version           = 1
        platform          = "windows-tpm-client"
        binding           = $env:BINDING
        build_digest      = $env:BUILD_DIGEST
        ak_cert           = (Hex-File $env:AK_CERT_DER)
        ek_cert           = (Hex-File $env:EK_CERT_DER)
        ek_ca_chain       = @(Read-EkChain $ekChainFiles)
        ak_name           = (Hex-File $env:TPM_AK_NAME_FILE)
        credential_activation = $activation
        quote_msg         = (Hex-File $quoteMsg)
        quote_sig         = (Hex-File $quoteSig)
        qualifying_data   = $env:BINDING
        pcr_bank          = "sha256"
        pcrs              = @(Read-Pcrs $pcrread)
    }
    $json = ($data | ConvertTo-Json -Depth 5) + "`n"

    if ($OutFile -eq "-") {
        Write-Output $json
    } else {
        Set-Content -Path $OutFile -Value $json -Encoding utf8
        Write-Output $OutFile
    }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
