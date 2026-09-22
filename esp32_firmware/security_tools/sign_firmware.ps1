# ==============================================================================
# ESP32 SECURE BOOT V2 — FIRMWARE SIGNING & VERIFICATION TOOL
# ==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$InputBin,

    [string]$OutputBin = "",
    [string]$KeyFile = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($KeyFile)) {
    $KeyFile = Join-Path $PSScriptRoot "..\keys\secure_boot_signing_key.pem"
}


# Auto-locate espsecure.exe
$espsecure = Get-Command "espsecure.exe" -ErrorAction SilentlyContinue
if (-not $espsecure) {
    $arduinoPath = "C:\Users\Manas\AppData\Local\Arduino15\packages\esp32\tools\esptool_py\5.2.0\espsecure.exe"
    if (Test-Path $arduinoPath) {
        $espsecure = $arduinoPath
    } else {
        Write-Error "espsecure.exe not found!"
    }
} else {
    $espsecure = $espsecure.Source
}

if (-not (Test-Path $InputBin)) {
    Write-Error "Input binary not found: $InputBin"
}

if (-not (Test-Path $KeyFile)) {
    Write-Error "Signing key not found: $KeyFile. Run generate_keys.ps1 first."
}

if ($OutputBin -eq "") {
    $dir = Split-Path $InputBin
    $name = [System.IO.Path]::GetFileNameWithoutExtension($InputBin)
    $ext = [System.IO.Path]::GetExtension($InputBin)
    $OutputBin = Join-Path $dir "${name}_signed${ext}"
}

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  ESP32 SECURE BOOT V2 SIGNING PIPELINE" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Input Binary  : $InputBin" -ForegroundColor Gray
Write-Host "Signing Key   : $KeyFile" -ForegroundColor Gray
Write-Host "Output Binary : $OutputBin" -ForegroundColor Gray

# Step 1: Sign the binary using Secure Boot v2 (RSA-3072)
Write-Host "`n[1/3] Signing binary with Secure Boot v2 (RSA-3072)..." -ForegroundColor Yellow
& $espsecure sign-data --version 2 --keyfile $KeyFile --output $OutputBin $InputBin
Write-Host "  [+] Binary signed successfully." -ForegroundColor Green

# Step 2: Inspect the attached signature block v2
Write-Host "`n[2/3] Extracting Signature Block (v2) Information..." -ForegroundColor Yellow
& $espsecure signature-info-v2 $OutputBin

# Step 3: Verify the signature
Write-Host "`n[3/3] Performing Cryptographic Verification Check..." -ForegroundColor Yellow
& $espsecure verify-signature --version 2 --keyfile $KeyFile $OutputBin
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n  >>> SIGNATURE VERIFICATION: PASSED (Authentic & Untampered) <<<" -ForegroundColor Green
} else {
    Write-Host "`n  >>> SIGNATURE VERIFICATION: FAILED <<<" -ForegroundColor Red
}

Write-Host "========================================================" -ForegroundColor Cyan
