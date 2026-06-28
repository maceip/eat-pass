#Requires -Version 5.1
<#
.SYNOPSIS
  Collect a Windows desktop TPM2 client attestation bundle for eat-pass.

.DESCRIPTION
  Requires tpm2-tools (tpm2-tss) on PATH — same JSON schema as collect-desktop-tpm.sh.
  Policy allowlist uses desktop_build_id_hash(build_digest):
    eat-pass desktop-hash-build C:\path\to\agent.exe

.PARAMETER OutFile
  Output path, or "-" to write JSON to stdout (SDK mode).

.EXAMPLE
  $env:BINDING = "<64-hex>"
  $env:BUILD_DIGEST = "<64-hex>"
  .\collect-desktop-tpm-windows.ps1 -OutFile bundle.json
#>
param(
    [string]$OutFile = "desktop-tpm-bundle.json"
)

$ErrorActionPreference = "Stop"

if (-not $env:BINDING) { throw "set BINDING to 32-byte hex (eat-pass channel binding)" }
if (-not $env:BUILD_DIGEST) { throw "set BUILD_DIGEST to sha256(agent binary) hex" }

$tools = @("tpm2_createek", "tpm2_createak", "tpm2_quote", "tpm2_readpublic")
foreach ($t in $tools) {
    if (-not (Get-Command $t -ErrorAction SilentlyContinue)) {
        throw "missing $t — install tpm2-tools (tpm2-tss) on Windows"
    }
}

$work = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_.FullName }
try {
    $ctx = Join-Path $work "ctx"
    $akCtx = Join-Path $work "ak.ctx"
    $ekPub = Join-Path $work "ek.pub"
    $akPub = Join-Path $work "ak.pub"
    $akName = Join-Path $work "ak.name"
    $akCert = Join-Path $work "ak.der"
    $quoteMsg = Join-Path $work "quote.msg"
    $quoteSig = Join-Path $work "quote.sig"
    $pcrs = Join-Path $work "pcr.bin"

    & tpm2_createek -c $ctx -G rsa -u $ekPub 2>$null
    & tpm2_createak -C $ctx -c $akCtx -G ecc -g sha256 -s ecdsa -u $akPub -n $akName 2>$null

    [byte[]]$pcr0 = @(0, 0, 0, 0)
    [IO.File]::WriteAllBytes($pcrs, $pcr0)

    & tpm2_quote -c $akCtx -l "sha256:0" -q $quoteMsg -m $quoteSig -g sha256 `
        -L $env:BINDING -o $pcrs 2>$null

    try {
        & tpm2_readpublic -c $akCtx -o $akCert -f der 2>$null
    } catch {
        Copy-Item $akPub $akCert
    }

    function Hex-File($path) {
        -join ([System.BitConverter]::ToString([IO.File]::ReadAllBytes($path)).Replace("-", "").ToLower())
    }

    $data = [ordered]@{
        version           = 1
        platform          = "windows-tpm-client"
        binding           = $env:BINDING
        build_digest      = $env:BUILD_DIGEST
        ak_cert           = (Hex-File $akCert)
        quote_msg         = (Hex-File $quoteMsg)
        quote_sig         = (Hex-File $quoteSig)
        qualifying_data   = $env:BINDING
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
