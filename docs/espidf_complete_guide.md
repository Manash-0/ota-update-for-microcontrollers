# ESP-IDF Complete Guide: Setup, Flashing, and Attack Simulations (ESP32-C6)

This step-by-step guide is written specifically for the **Smartelex ESP32-C6 Pico Dev Board (USB-C)**. It covers everything from installing the official Espressif toolchain on Windows to configuring hardware security engines and simulating all 5 evaluation attack scenarios using ESP-IDF command-line tools.

---

## 1. Quick Concept: ESP-IDF vs. Arduino for Hardware Security

| Capability | Arduino IDE (Track A) | ESP-IDF (Track B) |
| :--- | :--- | :--- |
| **Primary Focus** | Rapid prototyping, Wi-Fi, HTTPS OTA, SUIT/COSE Manifest parsing | Silicon-level hardware root of trust |
| **Secure Boot v2** | Verification in software only | **Enforced in Hardware Mask ROM** |
| **Flash Encryption** | Transparent if enabled, but cannot configure eFuses | **Full AES-128/256-XTS configuration & eFuse burning** |
| **Anti-Rollback** | Software monotonic sequence counter | **Physical silicon eFuse monotonic versioning** |
| **Low-Level Tools** | Basic GUI uploader | `esptool.py`, `espsecure.py`, `espefuse.py`, `idf.py` |

---

## 2. Environment Setup on Windows

### Step 2.1: Download and Install ESP-IDF
1. Download the **ESP-IDF v5.2 or v5.3 Windows Offline Installer** from Espressif:
   - Official Link: [dl.espressif.com/dl/esp-idf/](https://dl.espressif.com/dl/esp-idf/)
   - Select **ESP-IDF v5.2.x Offline Installer** (~1.2 GB).
2. Run the installer:
   - Accept default destination: `C:\Espressif`
   - When asked for components, leave all checked (Python, Git, CMake, Ninja, Toolchains).
   - Complete installation (takes ~3–5 minutes).
3. Once finished, open **Start Menu** and search for:
   ```text
   ESP-IDF 5.2 PowerShell
   ```
   *(Always use this dedicated shortcut, as it automatically sets up all required compiler paths, environment variables, and Python virtual environments).*

### Step 2.2: Identify Your USB COM Port
1. Plug the Smartelex ESP32-C6 Pico into your Windows PC via USB-C.
2. In the ESP-IDF PowerShell window, run:
   ```powershell
   Get-CimInstance Win32_SerialPort | Select-Object DeviceID, Description
   ```
   Note your port (e.g. `COM4`, `COM5`, or `COM8`).

---

## 3. Basic Project Setup, Building, and Flashing

Navigate to the project's `idf_hardware/` directory:

```powershell
cd c:\Users\Manas\Desktop\xyz\btp\idf_hardware
```

### Step 3.1: Set Target to ESP32-C6
Configure the build system for the RISC-V ESP32-C6 architecture:
```powershell
idf.py set-target esp32c6
```
*(This loads the RISC-V toolchain `riscv32-esp-elf` and merges [`sdkconfig.defaults`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/sdkconfig.defaults)).*

### Step 3.2: Generate the Secure Boot v2 Signing Key
Before building with Secure Boot v2 enabled, generate an RSA-3072 private signing key:
```powershell
espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem
```
> [!NOTE]
> This key signs the 2nd-stage bootloader and application binaries. It is automatically referenced by `sdkconfig.defaults` (`CONFIG_SECURE_BOOT_SIGNING_KEY="secure_boot_signing_key.pem"`).

### Step 3.3: Build the Project
Compile the bootloader, partition table, and application:
```powershell
idf.py build
```
Once build succeeds, you will see output like:
```text
Project build complete. To flash, run this command:
esptool.py -p COM5 -b 460800 --before default_reset --after hard_reset --chip esp32c6 write_flash ...
```

### Step 3.4: Flash and Monitor the Board
Flash the compiled binaries to your ESP32-C6 and open the live serial monitor:
```powershell
idf.py -p COM5 flash monitor
```
*(Replace `COM5` with your actual port. Press `Ctrl + ]` to exit the monitor).*

#### Expected Console Boot Output:
```text
I (31) boot: ESP-IDF v5.2.1 2nd stage bootloader
I (35) boot: compile time May 18 2026 00:30:12
I (38) boot: chip revision: v0.0
I (41) boot.esp32c6: SPI Speed   : 80MHz
I (45) boot.esp32c6: SPI Mode    : DIO
I (50) boot.esp32c6: SPI Flash Size : 4MB
I (54) boot: Partition Table:
I (58) boot: ## Label            Usage          Type ST Sub   Offset   Length
I (65) boot:  0 nvs              WiFi data        01 02 00009000 00004000
I (73) boot:  1 otadata          OTA data         01 00 0000d000 00002000
I (80) boot:  2 phy_init         RF data          01 01 0000f000 00001000
I (88) boot:  3 ota_0            OTA app          00 10 00010000 001c0000
I (95) boot:  4 ota_1            OTA app          00 11 001d0000 001c0000
I (103) boot:  5 storage          SPIFFS          01 82 00390000 00060000
========================================================
   ESP32-C6 HARDWARE SECURITY EVALUATION PLATFORM       
   B.Tech Project: Secure Firmware Updates for IoT     
========================================================
I (125) HARDWARE_SECURITY: [+] Secure Boot v2: ACTIVE & ENFORCED IN HARDWARE
I (135) HARDWARE_SECURITY: [+] Hardware Flash Encryption: ACTIVE (Development Mode)
I (145) HARDWARE_SECURITY: [*] App Secure Version: 1
I (155) HARDWARE_SECURITY: [*] Booted Partition: 'ota_0' @ 0x00010000 (1792 KB)
I (165) HARDWARE_SECURITY: [+] System idling safely. All hardware security engines active.
```

---

## 4. Hardware Security Configuration Explained

In [`sdkconfig.defaults`](file:///c:/Users/Manas/Desktop/xyz\btp\idf_hardware\sdkconfig.defaults), safety and evaluation modes are pre-configured:

```ini
# 1. Secure Boot v2 (Development / Insecure Mode)
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y
CONFIG_SECURE_BOOT_SIGNING_KEY="secure_boot_signing_key.pem"
CONFIG_SECURE_BOOT_INSECURE=y              # <--- Keeps UART download mode enabled (board cannot be bricked)

# 2. Flash Encryption (Development Mode)
CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y # <--- Allows reflashing in plaintext via USB
CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC=y

# 3. Monotonic Hardware Anti-Rollback
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
CONFIG_BOOTLOADER_APP_SEC_VER=1            # <--- Silicon eFuse security counter value

# 4. A/B Dual Partitioning with Automatic Rollback
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
```

> [!WARNING]
> **WHY WE USE DEVELOPMENT MODE (`INSECURE=y`):**
> If you burn Release Mode eFuses (`CONFIG_SECURE_BOOT_INSECURE=n`), the chip permanently locks UART flashing. Any mistake or unsigned code will **permanently brick the board**. Development Mode gives you 100% of the cryptographic verification while allowing you to re-flash freely.

---

## 5. Simulating Each Attack Scenario in ESP-IDF

We have automated these simulations with a dedicated script, or you can run each command manually.

### Automated Simulation Runner:
In the ESP-IDF terminal:
```powershell
cd c:\Users\Manas\Desktop\xyz\btp\idf_hardware
python simulate_idf_attacks.py
```

---

### Scenario 1: Valid Boot & Cryptographic Signature Verification
* **Objective:** Prove that the binary has a valid Secure Boot v2 signature block appended to it.
* **Manual Command:**
  ```powershell
  espsecure.py verify_signature --version 2 -k secure_boot_signing_key.pem build/main.bin
  ```
* **Expected Output:**
  ```text
  Signature is valid!
  Verification successful for version 2 signature block.
  ```

---

### Scenario 2: Tampered Firmware Attack Simulation (Bit-Flip in Bytecode)
* **Objective:** Prove that if an attacker modifies 1 byte in the compiled binary, the signature is invalidated and Secure Boot rejects it.
* **Execution Steps:**
  1. Make a copy of the valid application binary:
     ```powershell
     Copy-Item build/main.bin build/main_tampered.bin
     ```
  2. Flip a byte in the code segment (offset 512):
     ```powershell
     python -c "f=open('build/main_tampered.bin','r+b'); f.seek(512); b=f.read(1); f.seek(512); f.write(bytes([b[0]^0xFF])); f.close(); print('[*] Byte flipped at offset 512')"
     ```
  3. Verify the tampered binary with `espsecure.py`:
     ```powershell
     espsecure.py verify_signature --version 2 -k secure_boot_signing_key.pem build/main_tampered.bin
     ```
* **Expected Result:**
  ```text
  Signature is INVALID!
  Verification FAILED: RSA signature check failed over image digest.
  ```
* **Hardware Result:** If flashed, the ROM bootloader halts with:
  ```text
  E (12) secure_boot_v2: Secure Boot V2 verification failed
  E (16) boot: Bootloader signature verification failed (-1)
  ```

---

### Scenario 3: Monotonic Anti-Rollback / Downgrade Attack
* **Objective:** Demonstrate that the bootloader checks `CONFIG_BOOTLOADER_APP_SEC_VER` and refuses to run an older version.
* **Execution Steps:**
  1. Inspect the compiled binary's embedded header (`esp_app_desc_t`):
     ```powershell
     esptool.py --chip esp32c6 image_info build/main.bin
     ```
  2. Note line:
     ```text
     Secure version: 1
     ```
  3. Change `CONFIG_BOOTLOADER_APP_SEC_VER=0` in `sdkconfig` and rebuild as `build/main_v0.bin`.
  4. If an attacker flashes `main_v0.bin` onto a chip running security version 1, the bootloader rejects it:
     ```text
     W (45) boot: App version 0 is lower than security version 1. Rollback rejected!
     ```

---

### Scenario 4: Physical Flash Extraction / Bus Sniffing Attack (Flash Encryption)
* **Objective:** Prove that reading the SPI flash chip via external programmer returns ciphertext, protecting code and credentials.
* **Execution Steps:**
  1. Extract a 4 KB chunk of raw flash from the application offset (`0x10000`):
     ```powershell
     esptool.py -p COM5 read_flash 0x10000 0x1000 extracted_flash.bin
     ```
  2. Inspect the extracted dump in hex / ASCII:
     ```powershell
     Format-Hex extracted_flash.bin | Select-Object -First 20
     ```
  3. Measure Shannon Entropy:
     ```powershell
     python -c "import math; d=open('extracted_flash.bin','rb').read(); e=-sum((d.count(b)/len(d))*math.log2(d.count(b)/len(d)) for b in set(d)); print(f'[*] Extracted Flash Entropy: {e:.4f} / 8.0000 (Ciphertext > 7.9)')"
     ```
* **Expected Result:**
  - Plaintext code has entropy ~5.2–6.1 with visible strings (e.g. `HARDWARE_SECURITY`).
  - Encrypted flash has entropy **> 7.95**, looking completely random with **zero readable ASCII strings**.

---

### Scenario 5: Two-Phase Commit & Automatic Rollback
* **Objective:** Prove that if candidate firmware in `ota_1` fails its health check, the bootloader recovers automatically by falling back to `ota_0`.
* **Execution Steps:**
  1. Flash `ota_0` (Golden V1).
  2. Flash candidate build into `ota_1` and set `otadata` state to `ESP_OTA_IMG_PENDING_VERIFY`.
  3. Boot the board. If the app panics or calls:
     ```c
     esp_ota_mark_app_invalid_rollback_and_reboot();
     ```
  4. The 2nd-stage bootloader marks `ota_1` invalid in the `otadata` partition and reboots directly back into `ota_0`.

---

## 6. Safe eFuse Inspection Commands

You can inspect the hardware eFuse registers at any time without burning or modifying any bits:

```powershell
espefuse.py -p COM5 summary
```

#### Key eFuse Registers for ESP32-C6:
- `BLOCK_KEY0` / `BLOCK_KEY1`: Stores RSA-3072 public key digest for Secure Boot v2.
- `BLOCK_KEY2`: Stores 256-bit AES-XTS key for Flash Encryption.
- `SECURE_VERSION`: Monotonic counter bits for anti-rollback.
- `SECURE_BOOT_EN`: Hardware Secure Boot enforcement bit.
- `SPI_BOOT_CRYPT_CNT`: Flash encryption enable counter (odd count = encrypted).

---

## 7. Summary Cheat-Sheet for Final Review

| Step | Command | Purpose |
| :--- | :--- | :--- |
| **Set Chip** | `idf.py set-target esp32c6` | Select RISC-V C6 architecture |
| **Gen Key** | `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem` | Generate RSA-3072 root key |
| **Build** | `idf.py build` | Compile bootloader & app |
| **Flash** | `idf.py -p COM5 flash monitor` | Upload and view console |
| **Verify Sig** | `espsecure.py verify_signature --version 2 -k secure_boot_signing_key.pem build/main.bin` | Prove Secure Boot signature |
| **Dump Flash** | `esptool.py -p COM5 read_flash 0x10000 0x1000 extracted_flash.bin` | Prove Flash Encryption |
| **Read eFuses** | `espefuse.py -p COM5 summary` | Non-destructive hardware audit |
| **Auto Demo** | `python simulate_idf_attacks.py` | Run all 5 simulations in 1 command |
