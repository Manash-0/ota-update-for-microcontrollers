# ==============================================================================
# ESP32 FLASH ENCRYPTION (AES-256) — SIMULATION & VERIFICATION TOOL
# ==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$InputBin,

    [string]$KeyFile = "",
    [int]$FlashAddress = 0x10000
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($KeyFile)) {
    $KeyFile = Join-Path $PSScriptRoot "..\keys\flash_encryption_key.bin"
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
    Write-Error "Flash encryption key not found: $KeyFile. Run generate_keys.ps1 first."
}

$dir = Split-Path $InputBin
$name = [System.IO.Path]::GetFileNameWithoutExtension($InputBin)
$encryptedBin = Join-Path $dir "${name}_encrypted.bin"
$decryptedBin = Join-Path $dir "${name}_decrypted.bin"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  ESP32 FLASH ENCRYPTION (AES-256) SIMULATION" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Input Binary  : $InputBin" -ForegroundColor Gray
Write-Host "Key File      : $KeyFile" -ForegroundColor Gray
Write-Host "Flash Address : 0x$($FlashAddress.ToString('X'))" -ForegroundColor Gray

# Step 1: Encrypt the binary
Write-Host "`n[1/4] Encrypting binary for SPI Flash at address 0x$($FlashAddress.ToString('X'))..." -ForegroundColor Yellow
& $espsecure encrypt-flash-data --keyfile $KeyFile --address $FlashAddress --output $encryptedBin $InputBin
Write-Host "  [+] Encrypted Flash Image: $encryptedBin" -ForegroundColor Green

# Step 2: Compare Plaintext vs Encrypted Ciphertext
Write-Host "`n[2/4] Inspecting Physical Flash Data (Snooping Defense)..." -ForegroundColor Yellow
$plainBytes = [System.IO.File]::ReadAllBytes($InputBin)
$cipherBytes = [System.IO.File]::ReadAllBytes($encryptedBin)

$plainSample = [System.BitConverter]::ToString($plainBytes[0..31])
$cipherSample = [System.BitConverter]::ToString($cipherBytes[0..31])

Write-Host "  [-] Plaintext (First 32 bytes) : $plainSample" -ForegroundColor Gray
Write-Host "  [-] Encrypted (First 32 bytes) : $cipherSample" -ForegroundColor Magenta

# Step 3: Decrypt the binary back (Hardware Emulation)
Write-Host "`n[3/4] Hardware Decryption Emulation (Internal MMU read)..." -ForegroundColor Yellow
& $espsecure decrypt-flash-data --keyfile $KeyFile --address $FlashAddress --output $decryptedBin $encryptedBin
Write-Host "  [+] Decrypted Image: $decryptedBin" -ForegroundColor Green

# Step 4: Verify SHA-256 Hashes
Write-Host "`n[4/4] Verifying Byte-for-Byte Cryptographic Integrity..." -ForegroundColor Yellow
$hashOriginal = (Get-FileHash -Path $InputBin -Algorithm SHA256).Hash
$hashDecrypted = (Get-FileHash -Path $decryptedBin -Algorithm SHA256).Hash

Write-Host "  [-] Original SHA-256  : $hashOriginal" -ForegroundColor White
Write-Host "  [-] Decrypted SHA-256 : $hashDecrypted" -ForegroundColor White

if ($hashOriginal -eq $hashDecrypted) {
    Write-Host "`n  >>> INTEGRITY CONFIRMED: AES-256 REVERSIBILITY VERIFIED (100% MATCH) <<<" -ForegroundColor Green
} else {
    Write-Host "`n  >>> INTEGRITY ERROR: HASH MISMATCH <<<" -ForegroundColor Red
}

Write-Host "========================================================" -ForegroundColor Cyan
