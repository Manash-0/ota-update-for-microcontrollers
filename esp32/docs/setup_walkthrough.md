# End-to-End Setup Walkthrough Guide: ESP32-C6 Secure OTA

This comprehensive guide covers everything from hardware setup, key generation, and Arduino flashing to ESP-IDF hardware security configuration and attack matrix evaluation.

---

## Guide 1: Environment & Toolchain Setup

### 1.1 Arduino IDE 2.x Configuration
1. **Download & Install:** Install Arduino IDE 2.3+ from [arduino.cc](https://www.arduino.cc/en/software).
2. **Add ESP32 Board Package (v3.0.0+ required for ESP32-C6):**
   - In Arduino IDE, go to `File` -> `Preferences`.
   - In *Additional Board Manager URLs*, paste:
     ```text
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
   - Go to `Tools` -> `Board` -> `Boards Manager...`, search for `esp32` by Espressif, and install version **3.0.0 or later**.
3. **Board Selection & Critical USB-CDC Settings:**
   - Connect your Smartelex ESP32-C6 Pico USB-C cable to your PC.
   - Go to `Tools` -> `Board` -> `esp32` -> **ESP32C6 Dev Module**.
   - Go to `Tools` -> `Port` and select the active COM port (e.g. `COM5`).
   - **CRITICAL SETTINGS IN TOOLS MENU:**
     - **USB CDC On Boot:** `Enabled` *(Crucial: allows `Serial.print()` to output over native USB-C)*
     - **Flash Size:** `4MB (32Mb)`
     - **Partition Scheme:** `Custom` *(uses our `partitions.csv`)*
     - **Upload Speed:** `921600`
4. **Install Required Arduino Library:**
   - Go to `Tools` -> `Manage Libraries...`.
   - Search for **ArduinoJson** by Benoit Blanchon and click **Install**.

### 1.2 Python Server Dependencies (On Laptop)
Open PowerShell in the project directory:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\esp32\server
pip install cryptography cbor2 requests
```

---

## Guide 2: Cryptographic Keys & Local OTA Server

### 2.1 Generate Keys and C-Headers
In PowerShell:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\esp32\server
python gen_keys.py
```
**What this does:**
* Generates Root CA (`ca.crt`, `ca.key`)
* Generates Server TLS certificate (`server.crt`, `server.key`) with SAN for your local IP
* Generates Device mTLS credentials (`client.crt`, `client.key`)
* Generates Firmware Signing RSA keypair (`firmware_sign_priv.pem`, `firmware_sign_pub.pem`)
* Automatically formats and writes `ca_cert.h`, `client_cert.h`, and `firmware_pubkey.h` directly into `esp32/arduino/ota_client/`!

### 2.2 Start the Local HTTPS Server
```powershell
python ota_server.py
```
* **Firewall Tip:** If Windows Defender Firewall shows a popup, click **Allow access** on Private networks.
* **Hotspot Tip:** When testing on mobile hotspot or home Wi-Fi, ensure your laptop and ESP32-C6 are on the same Wi-Fi subnet. Note the IP printed by the server (e.g. `10.48.76.130` or `192.168.1.x`).

---

## Guide 3: Arduino Client Execution (Track A Live Demo)

### 3.1 Configure secrets.h
Open `esp32/arduino/ota_client/secrets.h` in Arduino IDE or VS Code:
```cpp
#define WIFI_SSID         "Your_WiFi_Name"
#define WIFI_PASSWORD     "Your_WiFi_Password"
#define OTA_SERVER_HOST   "10.48.76.130"   // IP printed by ota_server.py
#define OTA_SERVER_PORT   8443
#define DEVICE_ID         "ESP32C6-SMARTELEX-01"
#define ENABLE_MTLS       false
#define FIRMWARE_VERSION  "1.0.0"
#define SEQUENCE_NUMBER   1
#define SIMULATE_BUGGY_V2 false
```

### 3.2 Upload V1 Baseline Firmware
1. In Arduino IDE, open `esp32/arduino/ota_client/ota_client.ino`.
2. Click **Upload** (`Ctrl+U`).
3. Once flashed, open **Serial Monitor** at **115200 baud**.
4. Expected log lines:
   ```text
   ========================================================
      ESP32-C6 SECURE OTA FIRMWARE FRAMEWORK (TRACK A)     
   ========================================================
    [*] Firmware Version:     1.0.0
    [*] Sequence Number:      1
    [*] Device ID:            ESP32C6-SMARTELEX-01
   ----------------- Partition Diagnostics -----------------
   [*] Currently Running Partition: ota_0 (Offset 0x00010000)
   [+] Wi-Fi Connected! IP: 10.48.76.x
   ```

### 3.3 Compile and Stage V2 Candidate Firmware
1. In `secrets.h`, change:
   ```cpp
   #define FIRMWARE_VERSION  "2.0.0"
   #define SEQUENCE_NUMBER   2
   ```
2. In Arduino IDE menu, click **Sketch** -> **Export Compiled Binary** (`Ctrl+Alt+S`).
3. Locate the compiled `.bin` file in the sketch folder `build/esp32.esp32.esp32c6/` and copy it:
   ```powershell
   Copy-Item esp32\arduino\ota_client\build\esp32.esp32.esp32c6\ota_client.ino.bin esp32\server\firmware\firmware_v2.bin
   ```
4. Build the authentic SUIT manifest:
   ```powershell
   cd esp32\server
   python build_manifest.py --bin firmware\firmware_v2.bin --key keys\firmware_sign_priv.pem --seq 2 --ver 2.0.0
   ```

### 3.4 Trigger Live OTA & Demonstrate Health Check
1. On the ESP32-C6 Serial Monitor, press `u` and hit Enter (or wait for auto-trigger).
2. The device logs the full cryptographic update sequence:
   * TLS Handshake established
   * SUIT Manifest downloaded & RSA-2048 signature validated
   * Binary streamed into `ota_1` partition
   * SHA-256 hash verified
   * Auto-reboot into candidate partition!
3. On reboot, observe the **Two-Phase Commit**:
   ```text
   [*] Currently Running Partition: ota_1 (Offset 0x001D0000)
   [*] Running Image State: PENDING_VERIFY (Candidate Under Evaluation)
   [+] ALL HEALTH CHECKS PASSED!
   [+] Executing Two-Phase Commit: Marking image as permanently VALID.
   ```

---

## Guide 4: Hardware Security Setup (Track B: ESP-IDF)

> [!WARNING]
> **CRITICAL eFuse SAFETY NOTICE:**
> eFuses on the ESP32-C6 are physical, one-way microscopic silicon fuses. Once burned, bits cannot be unburned!
> **ALWAYS** use Development Mode (`CONFIG_SECURE_BOOT_INSECURE=y`, `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y`).
> This leaves UART download mode enabled and prevents permanently bricking your board.

### 4.1 Install ESP-IDF (When ready for Track B)
* Download the **ESP-IDF Windows Offline Installer** (v5.2 or v5.3) from Espressif's website:
  [dl.espressif.com/dl/esp-idf/](https://dl.espressif.com/dl/esp-idf/)
* Launch "ESP-IDF 5.2 PowerShell" from Start Menu.

### 4.2 Build and Flash Track B Project
In the ESP-IDF terminal:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\esp32\idf_hardware
idf.py set-target esp32c6
idf.py build
idf.py -p COM5 flash monitor
```

### 4.3 Inspect eFuses and Hardware Root of Trust
To inspect eFuse status without burning anything:
```powershell
espefuse.py -p COM5 summary
```
To verify signed bootloader with `espsecure.py`:
```powershell
espsecure.py verify_signature --version 2 -k secure_boot_signing_key.pem build/bootloader/bootloader.bin
```

---

## Guide 5: Executing the 9-Test Attack Matrix

Run the automated test runner from PowerShell:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\esp32\tests
python run_attack_matrix.py
```

### Manual Attack Reproduction:
* **Test 2 (Tampered Binary):** Invert 1 byte in `firmware_v2.bin`. Trigger OTA -> Serial shows `PAYLOAD HASH INTEGRITY MISMATCH... Update.abort()`.
* **Test 4 (Anti-Rollback):** Run `python build_manifest.py --bin firmware\firmware_v2.bin --old-seq`. Trigger OTA -> Serial shows `ANTI-ROLLBACK TRIGGERED`.
* **Test 5 (Buggy V2):** Build with `SIMULATE_BUGGY_V2 = true`. Device reboots into V2, health check fails, and device automatically rolls back to V1!
* **Test 8 (Bad Magic):** Run `python build_manifest.py --bin firmware\firmware_v2.bin --bad-magic`. Trigger OTA -> Serial shows `BAD MAGIC REJECTED: 0xDEADBEEF detected!`.
* **Test 9 (Unauthorized ID):** Send curl with fake ID:
  ```powershell
  curl -k -H "X-Device-ID: ROGUE_DEV" https://10.48.76.130:8443/ota/manifest.json
  # Result: HTTP 403 Forbidden
  ```

---

## Guide 6: Benchmarks Collection
Follow `docs/benchmarks.md`:
1. Record time for TLS handshake from serial monitor.
2. Record time for RSA-2048 verification.
3. Record transfer rate in KB/s.
4. Record free heap margin.

---

## Guide 7: Git Workflow & Security Hygiene

```powershell
cd c:\Users\Manas\Desktop\xyz\btp
git status
# Verify that keys/*.pem, client.key, and secrets.h are NOT listed as untracked files!
git add esp32/
git commit -m "feat: complete ESP32-C6 secure OTA framework with Track A Arduino, SUIT manifest, and attack matrix"
git tag -a final-review -m "Final B.Tech evaluation release"
git push origin main --tags
```

