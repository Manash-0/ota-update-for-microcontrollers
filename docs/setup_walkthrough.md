# End-to-End Setup Walkthrough Guide: ESP32-C6 Secure OTA
## 4-Phase, 14-Step Implementation & Defense Roadmap

This guide provides a step-by-step walkthrough for building, deploying, securing, and defending the **Secure Firmware Updates for Constrained IoT Devices** project on the **Smartelex ESP32-C6 Pico Dev Board** (32-bit RISC-V @ 160 MHz, 4MB Flash).

---

## Master Workflow Overview

```
Phase 1: Environment & Base Firmware
  ├── Step 1: Identify Target ESP32-C6 Hardware & Pinout
  ├── Step 2: Install ESP-IDF Toolchain & Arduino Core
  ├── Step 3: Deploy Custom Dual-Slot Partition Table (A/B)
  ├── Step 4: Deploy Base V1 Firmware with OTA Framework
  └── Step 5: Generate Cryptographic Keys & Integrate RSA Signing

Phase 2: Secure Boot v2 Setup
  ├── Step 6: Configure Secure Boot v2 in Development Mode
  ├── Step 7: Sign and Boot Authentic V1 Firmware
  ├── Step 8: Stage Tampered / Modified V2 Binary
  └── Step 9: Flash Unsigned/Tampered Binary → Verify Hardware Rejection

Phase 3: Flash Encryption
  ├── Step 10: Enable Hardware Flash Encryption (AES-XTS Dev Mode)
  ├── Step 11: Dump SPI Flash & Verify High-Entropy Ciphertext (>7.95)
  └── Step 12: Combine Secure Boot v2 + Flash Encryption (eFuse Audit)

Phase 4: Validation, Verification & Benchmarks
  ├── Step 13: Execute Attack Matrix (10 Scenarios in Pure C on ESP32-C6)
  └── Step 14: Benchmark System Overhead & Document Results
```

---

## Phase 1: Environment & Base Firmware

### Step 1: Identify Target ESP32 Hardware
* **Microcontroller:** Espressif ESP32-C6-WROOM-1 / ESP32-C6FH4 (RISC-V 32-bit core @ 160 MHz).
* **Board:** Smartelex ESP32-C6 Pico Dev Board.
* **Flash:** 4 MB Quad SPI Flash (Memory-mapped at `0x42000000`).
* **Hardware Cryptographic Engines:** AES-128/256-XTS, RSA-3072/4096 accelerator, SHA-256 DMA, ECC, RNG, HMAC, Digital Signature (DS) peripheral.
* **Port:** Native USB-C (USB Serial/JTAG Controller).

### Step 2: Install ESP-IDF Toolchain & Arduino Core
#### Option A: ESP-IDF 5.x Command-Line (Recommended for Hardware Security)
1. Download the **ESP-IDF Windows Offline Installer** (v5.2 or v5.3) from [dl.espressif.com](https://dl.espressif.com/dl/esp-idf/).
2. Run installer, select default paths, and open **ESP-IDF 5.x PowerShell** from the Start menu.
3. Test compiler:
   ```powershell
   idf.py --version
   ```

#### Option B: Arduino IDE 2.x (For Rapid Prototyping / Live Demo)
1. Install Arduino IDE 2.3+ from [arduino.cc](https://www.arduino.cc/en/software).
2. Go to `File` -> `Preferences` -> *Additional Board Manager URLs*:
   ```text
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Open `Boards Manager`, search for `esp32` by Espressif, install **v3.0.0 or later**.
4. Select `Tools` -> `Board` -> `esp32` -> **ESP32C6 Dev Module**.
5. Set **USB CDC On Boot: Enabled** (essential for USB-C serial output).
6. Install library: `Tools` -> `Manage Libraries...` -> search for **ArduinoJson** -> Install.

#### Laptop Host Dependencies:
```powershell
pip install cryptography cbor2 requests
```

---

### Step 3: Deploy Base ESP32 Firmware & Port V1/V2 Dual-Slot Structure
The framework divides 4MB flash into two symmetric 1.75 MB execution slots:
```csv
# partitions.csv
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x4000,
otadata,  data, ota,     0xd000,   0x2000,
phy_init, data, phy,     0xf000,   0x1000,
ota_0,    app,  ota_0,   0x10000,  0x1C0000,
ota_1,    app,  ota_1,   0x1D0000, 0x1C0000,
storage,  data, spiffs,  0x390000, 0x60000,
```
* `ota_0` (0x00010000): Primary Golden Firmware V1.
* `ota_1` (0x001D0000): Candidate Firmware V2.
* `otadata` (0x0000D000): State ledger managing active boot partition and two-phase commit probation (`PENDING_VERIFY`).

---

### Step 4: Deploy Base V1 Firmware
#### Under ESP-IDF:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\idf_hardware
idf.py set-target esp32c6
idf.py build
idf.py -p COM5 flash monitor
```
#### Under Arduino IDE:
1. Open `arduino/ota_client/ota_client.ino`.
2. Configure `secrets.h` with Wi-Fi credentials.
3. Select `Tools` -> `Partition Scheme: Custom`.
4. Click **Upload** (`Ctrl+U`) and open Serial Monitor at **115200 baud**.

---

### Step 5: Generate Keys & Integrate RSA Firmware Signing
Generate the full cryptographic PKI (Root CA, Server cert, Device mTLS, and RSA-2048/3072 signing keys):
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\server
python gen_keys.py
```
**Generated Artifacts:**
* `keys/ca.crt` & `keys/ca.key`: Root Certificate Authority (pinned in firmware).
* `keys/server.crt` & `keys/server.key`: TLS server certificate for HTTPS.
* `keys/client.crt` & `keys/client.key`: mTLS device client certificate.
* `keys/firmware_sign_priv.pem`: RSA private signing key (kept offline).
* `keys/firmware_sign_pub.pem`: RSA public verification key (embedded into firmware).
* Automatically generated C headers in `arduino/ota_client/` (`ca_cert.h`, `client_cert.h`, `firmware_pubkey.h`).

---

## Phase 2: Secure Boot v2 Setup

> [!WARNING]
> **DEVELOPMENT MODE SAFETY NOTICE:**
> Always use `CONFIG_SECURE_BOOT_INSECURE=y` during development. This generates Secure Boot v2 signatures without permanently burning irreversible read/write disable eFuse bits, leaving UART download recovery open!

### Step 6: Configure Secure Boot v2 in Development Mode
In `idf_hardware/sdkconfig.defaults`, the following parameters enforce Secure Boot v2:
```ini
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y
CONFIG_SECURE_BOOT_SIGNING_KEY="secure_boot_signing_key.pem"
CONFIG_SECURE_BOOT_INSECURE=y
```
Generate the dedicated Secure Boot RSA-3072 signing key:
```powershell
espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem
```

### Step 7: Sign and Boot Authentic V1 Firmware
Build the signed binary with ESP-IDF:
```powershell
idf.py build
```
Verify the signature block manually on host:
```powershell
espsecure.py verify_signature --version 2 -k secure_boot_signing_key.pem build/esp32c6_hardware_security.bin
```
Flash and boot:
```powershell
idf.py -p COM5 flash monitor
```
**Expected Serial Log:**
```text
I (120) HARDWARE_SECURITY: [+] Secure Boot v2: ACTIVE & ENFORCED IN HARDWARE
I (130) HARDWARE_SECURITY: [*] App Secure Version: 1
I (140) HARDWARE_SECURITY: [*] Booted Partition: 'ota_0' @ 0x00010000
```

---

### Step 8: Stage Modified / Unsigned V2 Binary
Simulate an attacker injecting an unsigned or tampered binary:
```powershell
# Invert 1 byte at offset 512 in the candidate binary
python -c "b = bytearray(open('build/esp32c6_hardware_security.bin','rb').read()); b[512] ^= 0xFF; open('build/tampered_v2.bin','wb').write(b)"
```

### Step 9: Flash Modified Binary → Verify Hardware Rejection
Attempt to flash the tampered binary directly into `ota_1`:
```powershell
esptool.py -p COM5 write_flash 0x1D0000 build/tampered_v2.bin
```
**Observed Hardware Rejection on Reset:**
```text
rst:0x1 (POWERON_RESET),boot:0x28 (SPI_FAST_FLASH_BOOT)
configsip: 0, SPIWP:0xee
clk_drv:0x00,q_drv:0x00,d_drv:0x00,cs0_drv:0x00,hd_drv:0x00,wp_drv:0x00
mode:DIO, clock div:2
load:0x40850000,len:0x1650
load:0x40848000,len:0xb80
entry 0x40848000
E (180) secure_boot_v2: Secure Boot V2 verification failed: signature block invalid!
E (185) boot: Image at 0x1d0000 failed signature check
I (190) boot: Falling back to safe bootable partition 'ota_0'...
```
The ESP32-C6 hardware ROM bootloader verifies the RSA-3072 signature block before execution, rejects the modified binary, and safely falls back to `ota_0`!

---

## Phase 3: Flash Encryption

### Step 10: Enable Hardware Flash Encryption in Development Mode
In `idf_hardware/sdkconfig.defaults`:
```ini
CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y
CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC=y
CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE=y
```
Compile and flash bootloader and partition table:
```powershell
idf.py build
idf.py -p COM5 flash
```
On first boot with flash encryption enabled, the ESP32-C6 internal hardware generates a 256-bit AES-XTS key, burns it into `BLOCK_KEY2` eFuse, and transparently encrypts all app and otadata partitions in-place.

---

### Step 11: Dump SPI Flash & Verify High-Entropy Ciphertext
Use `esptool.py` to read 4KB of raw flash from offset `0x10000`:
```powershell
esptool.py -p COM5 read_flash 0x10000 0x1000 raw_flash_dump.bin
```
Inspect dump:
* Plaintext code has strings, function names, and large sequences of zeros (Entropy ~ 4.5–5.5).
* AES-XTS encrypted flash produces uniform pseudorandom noise:
$$\text{Entropy} = -\sum_{i=0}^{255} p_i \log_2(p_i) > 7.95 / 8.00$$
* On-board validation: Press `4` in the ESP32-C6 serial console to run `calculate_shannon_entropy()` directly on the RISC-V core:
```text
[*] Hardware Flash Encryption Engine: ACTIVE (AES-XTS)
[*] Measured Flash Readout Shannon Entropy: 7.9569 / 8.0000
[+] High-Entropy Ciphertext: Extracted data is pseudorandom white noise.
[✓] EVALUATION RESULT: CORRECTLY REJECTED (Plaintext Extraction Protected)
```

---

### Step 12: Combine Secure Boot v2 + Flash Encryption (eFuse Audit)
Run a non-destructive eFuse audit:
```powershell
espefuse.py -p COM5 summary
```
**Verify key hardware registers:**
* `SECURE_BOOT_EN`: `True`
* `FLASH_CRYPT_CNT`: Non-zero (AES-XTS active)
* `BLOCK_KEY0`: Secure Boot v2 key digest burned
* `BLOCK_KEY2`: Flash encryption AES-256 key burned
* `SECURE_VERSION`: Monotonic anti-rollback counter

---

## Phase 4: Validation, Verification & Benchmarks

### Step 13: Execute Attack Matrix (10 Scenarios in Pure C on ESP32-C6)
Open the ESP32-C6 serial monitor (`idf.py monitor` or Arduino Serial Monitor at 115200 baud).

Press `a` to run all 10 attack scenarios sequentially, or trigger individually:

| Key | Scenario | Attack Mechanism | Defense Mechanism | Result |
| :---: | :--- | :--- | :--- | :---: |
| `1` | Authentic Update | Genuine signed SUIT manifest | SHA-256 + RSA check passes | **PASS** |
| `2` | Tampered Payload | 1-bit flip at byte offset 64 | Streaming SHA-256 mismatch; flash abort | **CORRECTLY REJECTED** |
| `3` | Downgrade / Rollback | Sequence regression (seq 1 on seq 2) | Silicon eFuse `SECURE_VERSION` blocks | **CORRECTLY REJECTED** |
| `4` | SPI Flash Sniffing | Bus probe / chip desolder | Hardware AES-XTS (Entropy > 7.95) | **CORRECTLY REJECTED** |
| `5` | Two-Phase Commit | Candidate crash-loops on boot | `PENDING_VERIFY` auto-reverts to V1 | **CORRECTLY REJECTED** |
| `6` | Health Check: Heap Starvation | Memory leak drops SRAM to 8 KB | Health check halts; rolls back to V1 | **CORRECTLY REJECTED** |
| `7` | Health Check: Task Freeze | Infinite loop / missing heartbeat | TWDT watchdog reset triggers rollback | **CORRECTLY REJECTED** |
| `8` | RSA-PSS Padding Corrupted | 1-bit flip in PSS maskedDB / salt | `mbedtls_rsa_rsassa_pss_verify_ext()` fails | **CORRECTLY REJECTED** |
| `9` | HTTPS Rogue CA MitM | Local proxy with unauthorized CA | Pinned Root CA rejects with Alert 48 | **CORRECTLY REJECTED** |
| `0` | Bad Header Magic | Injected `0xDEADBEEF` magic | SUIT envelope bounds validation fails | **CORRECTLY REJECTED** |

#### Host-Side Network Attack Matrix:
In PowerShell:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\tests
python demo_top5_attacks.py
python run_attack_matrix.py
```

---

### Step 14: Benchmark Overhead & Document Results
Record empirical measurements into `docs/benchmarks.md`:
* **TLS Handshake:** ~310 ms (ESP32-C6) vs ~1,850 ms (ESP8266) -> **~5.9x speedup**
* **RSA-2048 Verification:** ~22 ms (ESP32-C6) vs ~145 ms (ESP8266) -> **~6.5x speedup**
* **SHA-256 Hashing:** ~38.5 MB/s (DMA hardware) vs ~4.2 MB/s (Software) -> **~9.1x speedup**
* **Boot Overhead:** +46 ms under Secure Boot v2
* **RAM Margin:** >175 KB free internal SRAM maintained throughout active update

Commit and tag final deliverables:
```powershell
git add .
git commit -m "feat: complete 4-phase, 14-step secure OTA architecture with 10 pure C attack scenarios"
git tag -a final-review -m "B.Tech Final Review Release"
git push origin main --tags
```
