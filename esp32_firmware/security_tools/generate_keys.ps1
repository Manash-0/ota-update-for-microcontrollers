# ==============================================================================
# ESP32 SECURE BOOT & FLASH ENCRYPTION — KEY GENERATION TOOL
# ==============================================================================

param(
    [string]$KeyDir = "$PSScriptRoot\..\keys"
)

$ErrorActionPreference = "Stop"

# Auto-locate espsecure.exe from Arduino15 if not on PATH
$espsecure = Get-Command "espsecure.exe" -ErrorAction SilentlyContinue
if (-not $espsecure) {
    $arduinoPath = "C:\Users\Manas\AppData\Local\Arduino15\packages\esp32\tools\esptool_py\5.2.0\espsecure.exe"
    if (Test-Path $arduinoPath) {
        $espsecure = $arduinoPath
    } else {
        Write-Error "espsecure.exe not found! Please check ESP-IDF or Arduino ESP32 installation."
    }
} else {
    $espsecure = $espsecure.Source
}

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  ESP32 HARDWARE SECURITY KEY GENERATION" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Tool path: $espsecure" -ForegroundColor Gray

if (-not (Test-Path $KeyDir)) {
    New-Item -ItemType Directory -Path $KeyDir -Force | Out-Null
}

$signingKey = Join-Path $KeyDir "secure_boot_signing_key.pem"
$flashKey   = Join-Path $KeyDir "flash_encryption_key.bin"

# 1. Generate Secure Boot v2 RSA-3072 Signing Key
Write-Host "`n[1/3] Generating Secure Boot v2 Private Key (RSA-3072)..." -ForegroundColor Yellow
if (Test-Path $signingKey) {
    Write-Host "  [-] Key already exists at $signingKey (skipping overwrite)" -ForegroundColor Gray
} else {
    & $espsecure generate-signing-key --version 2 --scheme rsa3072 $signingKey
    Write-Host "  [+] Generated: $signingKey" -ForegroundColor Green
}

# 2. Extract Public Key & Digest for eFuses
$pubKey = Join-Path $KeyDir "secure_boot_public_key.pem"
Write-Host "`n[2/3] Extracting Public Verification Key..." -ForegroundColor Yellow
& $espsecure extract-public-key --version 2 --keyfile $signingKey $pubKey
Write-Host "  [+] Public Key: $pubKey" -ForegroundColor Green

# 3. Generate 256-bit Flash Encryption Key
Write-Host "`n[3/3] Generating Flash Encryption Key (AES-256)..." -ForegroundColor Yellow
if (Test-Path $flashKey) {
    Write-Host "  [-] Key already exists at $flashKey (skipping overwrite)" -ForegroundColor Gray
} else {
    & $espsecure generate-flash-encryption-key $flashKey
    Write-Host "  [+] Generated: $flashKey" -ForegroundColor Green
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " ALL KEYS GENERATED SUCCESSFULLY" -ForegroundColor Green
Write-Host " Location: $KeyDir" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Green
