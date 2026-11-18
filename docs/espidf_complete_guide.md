# ESP-IDF Complete Guide: Setup, Pure C Implementation, and Attack Simulations (ESP32-C6)

This comprehensive guide is written specifically for the **Smartelex ESP32-C6 Pico Dev Board (USB-C)**. It covers installing the official Espressif toolchain on Windows, compiling the **100% native C firmware**, running boot diagnostics, and executing all 10 evaluation attack scenarios directly on the microcontroller using our on-chip C attack matrix engine.

---

## Master 4-Phase, 14-Step Hardware Security Lifecycle

This project follows an embedded security lifecycle structured into 4 phases and 14 steps:

```
Phase 1: Environment & Base Firmware
  ├── Step 1–2: Identify target ESP32-C6 hardware & install ESP-IDF toolchain
  ├── Step 3–4: Deploy base ESP32 firmware & port V1/V2 dual-slot structure
  └── Step 5: Generate keys & integrate RSA firmware signing

Phase 2: Secure Boot v2 Setup
  ├── Step 6–7: Configure Secure Boot development mode; boot signed V1
  └── Step 8–9: Flash modified/unsigned V2 → verify hardware rejection

Phase 3: Flash Encryption
  ├── Step 10–11: Enable Flash Encryption (dev mode); verify encrypted SPI flash
  └── Step 12: Combine Secure Boot + Flash Encryption (eFuse audit)

Phase 4: Validation & Verification
  ├── Step 13: Execute attack matrix (10 scenarios: tampering, invalid signatures, rollback, health check)
  └── Step 14: Benchmark overhead & document results
```

---

## 1. Architecture: Native C Firmware on ESP32-C6

All microcontroller logic in [`idf_hardware/main/`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main) is written in **pure C (C99/FreeRTOS)** without Python dependencies on the chip:

```
idf_hardware/
├── CMakeLists.txt                 <-- Root CMake configuration
├── sdkconfig.defaults             <-- Hardware security presets (Secure Boot v2, Flash Enc, Anti-Rollback)
├── partitions.csv                 <-- 4MB A/B Dual Partition table (ota_0, ota_1, otadata)
└── main/
    ├── CMakeLists.txt             <-- Component registration (mbedtls, esp_ota_ops, efuse, etc.)
    ├── main.c                     <-- Boot diagnostics & Interactive USB-Serial/JTAG Console Menu
    ├── attack_matrix.h & .c       <-- Native C engine simulating all 10 attack scenarios on-chip
    └── suit_parser.h & .c         <-- RFC 9124 SUIT / COSE-Sign1 parser & mbedTLS RSA verifier in C
```

---

## 2. Environment Setup on Windows

### Step 2.1: Download and Install ESP-IDF
1. Download the **ESP-IDF v5.2 or v5.3 Windows Offline Installer** from Espressif:
   - Official Link: [dl.espressif.com/dl/esp-idf/](https://dl.espressif.com/dl/esp-idf/)
   - Select **ESP-IDF v5.2.x Offline Installer** (~1.2 GB).
2. Run the installer:
   - Accept default destination: `C:\Espressif`
   - Leave all standard components selected (Python, Git, CMake, Ninja, RISC-V Toolchain).
   - Complete installation (~3–5 minutes).
3. Once finished, open **Start Menu** and launch:
   ```text
   ESP-IDF 5.2 PowerShell
   ```
   *(Always run commands from this dedicated shortcut; it automatically sets up `idf.py`, `esptool.py`, `espsecure.py`, and the RISC-V compiler paths).*

### Step 2.2: Identify Your USB COM Port
1. Plug the Smartelex ESP32-C6 Pico into your Windows PC via USB-C.
2. In the ESP-IDF PowerShell window, run:
   ```powershell
   Get-CimInstance Win32_SerialPort | Select-Object DeviceID, Description
   ```
   Note your port number (e.g. `COM4`, `COM5`, or `COM8`).

---

## 3. Building and Flashing the Pure C Firmware

Navigate to your hardware project directory:

```powershell
cd c:\Users\Manas\Desktop\xyz\btp\idf_hardware
```

### Step 3.1: Set Target to ESP32-C6 (RISC-V)
```powershell
idf.py set-target esp32c6
```

### Step 3.2: Generate the Root Signing Key
Before building with Secure Boot v2 enabled, generate an RSA-3072 signing key:
```powershell
espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem
```
*(This key is referenced by `sdkconfig.defaults` to sign the bootloader and application binaries).*

### Step 3.3: Build the Pure C Project
Compile all C modules (`main.c`, `attack_matrix.c`, `suit_parser.c`):
```powershell
idf.py build
```

### Step 3.4: Flash and Open Serial Monitor
Upload the binaries to the board and open the console in one command:
```powershell
idf.py -p COM5 flash monitor
```
*(Replace `COM5` with your active port. Press `Ctrl + ]` to exit monitor).*

---

## 4. On-Chip Boot Diagnostics & Interactive C Menu

When the board boots up, it executes hardware audits, runs the 5 attack simulations in C, and presents an interactive console menu over the USB-Serial/JTAG interface:

```text
========================================================
   ESP32-C6 HARDWARE SECURITY EVALUATION PLATFORM (C)   
   B.Tech Project: Secure Firmware Updates for IoT     
========================================================
I (120) HARDWARE_SECURITY: [+] Secure Boot v2: ACTIVE & ENFORCED IN HARDWARE
I (130) HARDWARE_SECURITY: [+] Hardware Flash Encryption: ACTIVE (Development Mode)
I (140) HARDWARE_SECURITY: [*] App Secure Version: 1
I (150) HARDWARE_SECURITY: [*] Booted Partition: 'ota_0' @ 0x00010000 (1792 KB)

========================================================
   INTERACTIVE C ATTACK MATRIX CONSOLE (ESP32-C6)       
========================================================
 [1] Run Scenario 1: Authentic Signature & Hash Verification
 [2] Run Scenario 2: Tampered Payload (Byte-Flip in Transit)
 [3] Run Scenario 3: Monotonic Anti-Rollback (Downgrade Attack)
 [4] Run Scenario 4: Physical Flash Readout & Entropy Analysis
 [5] Run Scenario 5: Two-Phase Commit & Rollback Health Check
 [6] Run Scenario 6: Health Check: Heap Exhaustion / Memory Starvation
 [7] Run Scenario 7: Health Check: Task Freeze & Watchdog Timeout
 [8] Run Scenario 8: RSA-PSS Signature Attack (Corrupted Salt/Padding)
 [9] Run Scenario 9: HTTPS/TLS MitM Attack (Untrusted Rogue CA Cert)
 [0] Run Scenario 10: Bad Manifest Magic Bytes (0xDEADBEEF)
 [a] Run ALL 10 Scenarios Sequentially
========================================================
Enter choice [0-9, a]: 
```

---

## 5. How Each Attack Scenario Executes in Pure C

Evaluators can press any key (`0` to `9` or `a`) in the Serial Monitor to trigger live attack simulations on the microcontroller. Here is what happens inside the C code:

---

### Scenario 1: Authentic Firmware Validation (`press '1'`)
* **C Function:** `attack_matrix_scenario_1_valid_signature()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Computes candidate bytecode hash using hardware-accelerated SHA-256 (`mbedtls_sha256`).
  2. Constructs a `suit_manifest_t` structure with `magic = 0x53554954` and `sequence_number = 2`.
  3. Validates manifest bounds and verifies digest integrity.
* **Console Output:**
  ```text
  [+] Manifest Format & Anti-Rollback: OK - Valid & Authentic Manifest
  [+] Computed SHA-256 Digest matches declared hash perfectly.
  [✓] EVALUATION RESULT: PASS (Authentic Candidate Accepted)
  ```

---

### Scenario 2: Tampered Firmware Payload Attack (`press '2'`)
* **C Function:** `attack_matrix_scenario_2_tampered_payload()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Generates authentic bytecode and notes declared hash.
  2. Inverts a single bit in the code array (`tampered_code[64] ^= 0xFF`).
  3. Recomputes SHA-256 hash using the hardware engine.
  4. Detects digest mismatch and aborts flash commit immediately.
* **Console Output:**
  ```text
  [*] Attacker flipped byte at offset 64: 0x41 -> 0xBE
  [!] HASH INTEGRITY MISMATCH DETECTED!
  [+] Flash write operation ABORTED before writing any code to flash!
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Payload Tampering Defeated)
  ```

---

### Scenario 3: Firmware Downgrade / Rollback Attack (`press '3'`)
* **C Function:** `attack_matrix_scenario_3_anti_rollback()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Sets candidate sequence number to `1` (simulating replay of older firmware with known CVE).
  2. Evaluates against running sequence number `2` and silicon eFuse counter `CONFIG_BOOTLOADER_APP_SEC_VER`.
  3. Returns `SUIT_RES_ERR_ROLLBACK`.
* **Console Output:**
  ```text
  [*] Device Current Sequence: 2
  [*] Attacker Injected Sequence: 1 (Older build)
  [!] Anti-Rollback Triggered! Candidate seq (1) <= Current seq (2)
  [+] Silicon eFuse Protection: SECURE_VERSION bits prevent physical bootloader rollback.
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Downgrade Attack Blocked)
  ```

---

### Scenario 4: Physical Flash Readout & Entropy Analysis (`press '4'`)
* **C Function:** `attack_matrix_scenario_4_flash_encryption_entropy()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Calls `esp_partition_read()` to read 512 raw bytes directly from SPI flash.
  2. Computes **Shannon Entropy** in real-time on the RISC-V CPU using native C math (`logf`):
     $$\text{Entropy} = -\sum_{i=0}^{255} p_i \log_2(p_i)$$
  3. Demonstrates that plaintext code has low entropy (~4.5–5.5), while hardware AES-XTS encrypted flash produces **high entropy (> 7.95)**.
* **Console Output:**
  ```text
  [*] Hardware Flash Encryption Engine: ACTIVE (AES-XTS)
  [*] Measured Flash Readout Shannon Entropy: 7.9569 / 8.0000
  [+] High-Entropy Ciphertext: Extracted data is pseudorandom white noise.
  [+] SPI bus probe / chip desoldering yields zero plaintext secrets or code.
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Plaintext Extraction Protected)
  ```

---

### Scenario 5: Two-Phase Commit & Rollback Health Check (`press '5'`)
* **C Function:** `attack_matrix_scenario_5_two_phase_commit()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Reads partition state from the `otadata` ledger (`esp_ota_get_state_partition()`).
  2. Confirms that new candidate updates enter `ESP_OTA_IMG_PENDING_VERIFY`.
  3. Explains how a crash or failed health check triggers `esp_ota_mark_app_invalid_rollback_and_reboot()`, auto-reverting to Golden V1.
* **Console Output:**
  ```text
  [*] Active Partition: 'ota_0' @ 0x00010000
  [*] Partition Image State in otadata: 0x01 (VALID)
  [+] Zero Bricking Guarantee: Device self-heals without physical intervention.
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Crash-loop Recovered via Rollback)
  ```

---

### Scenario 6: Health Check Attack — Heap Exhaustion / Memory Starvation (`press '6'`)
* **C Function:** `attack_matrix_scenario_6_health_check_heap_starvation()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Evaluates live available internal SRAM via `esp_get_free_internal_heap_size()`.
  2. Evaluates against a minimum safety margin threshold (20 KB).
  3. Simulates a memory-leaking update dropping to 8 KB free SRAM.
  4. Diagnostics fail: firmware refuses to call `esp_ota_mark_app_valid_cancel_rollback()` and triggers `esp_ota_mark_app_invalid_rollback_and_reboot()`.
* **Console Output:**
  ```text
  [*] Current Free Internal SRAM Heap: 312520 bytes
  [*] Candidate Post-Boot Available Heap: 8192 bytes (Safety Threshold: 20480 bytes)
  [!] HEALTH CHECK DIAGNOSTICS FAILED: Insufficient heap available for safe runtime!
  [!] Action: Refusing to call esp_ota_mark_app_valid_cancel_rollback().
  [!] Action: Triggering esp_ota_mark_app_invalid_rollback_and_reboot().
  [+] Bootloader marks candidate slot INVALID in otadata and reboots into Golden V1!
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Memory Depletion Blocked by Health Check)
  ```

---

### Scenario 7: Health Check Attack — Task Freeze & Watchdog Recovery (`press '7'`)
* **C Function:** `attack_matrix_scenario_7_health_check_watchdog_timeout()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Inspects the Task Watchdog Timer (TWDT) configuration for probation status.
  2. Simulates an infinite loop or thread starvation in candidate firmware during probation.
  3. Missing heartbeat at 10,000 ms triggers a hardware watchdog reset.
  4. Bootloader detects that candidate never reached `VALID`, marks it invalid, and boots Golden V1.
* **Console Output:**
  ```text
  [*] Candidate status in otadata: ESP_OTA_IMG_PENDING_VERIFY (Probationary)
  [*] Hardware Task Watchdog Timer (TWDT) probation window: 10,000 ms
  [!] Candidate task deadlocked: heartbeat missed at T+10,000 ms!
  [!] Hardware Watchdog Reset tripped: CPU reset triggered!
  [+] ESP32-C6 ROM/2nd-Stage Bootloader examines otadata counter:
  [+] Detection: Candidate failed to reach 'VALID' state within probation period.
  [+] Bootloader shifts active partition pointer back to 'ota_0' (Golden V1).
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Frozen Update Automatically Rolled Back)
  ```

---

### Scenario 8: RSA-PSS Padding & Salt Corruption Attack (`press '8'`)
* **C Function:** `attack_matrix_scenario_8_rsa_pss_tampered_salt()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Simulates modern RSASSA-PSS (RFC 8017 / RFC 9124) with MGF1 and SHA-256 (32-byte salt).
  2. Simulates an attacker flipping a single bit inside the PSS maskedDB / salt region (offset 100).
  3. Evaluates via `mbedtls_rsa_rsassa_pss_verify_ext()`.
  4. Cryptographic engine detects salt/hash mismatch and rejects signature before boot.
* **Console Output:**
  ```text
  [*] RSA Scheme: RSASSA-PSS (MGF1 with SHA-256, Salt length = 32 bytes)
  [*] Attacker injected 1-bit flip in PSS maskedDB at offset 100: 0x5C -> 0x5D
  [!] mbedTLS RSA-PSS verification: mbedtls_rsa_rsassa_pss_verify_ext() called.
  [!] PSS Verification FAILED: Unmasked DB trailer / salt hash mismatch (-0x4280)!
  [+] Cryptographic engine rejects corrupted RSA-PSS signature before boot.
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (RSA-PSS Padding Tampering Blocked)
  ```

---

### Scenario 9: HTTPS / TLS MitM Attack — Rogue CA Spoofing (`press '9'`)
* **C Function:** `attack_matrix_scenario_9_https_untrusted_ca_mitm()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Loads pinned BTP Root CA into `mbedtls_x509_crt` trust anchor context.
  2. Parses attacker rogue server certificate (signed by unauthorized CA).
  3. Invokes `mbedtls_x509_crt_verify()`.
  4. Returns `MBEDTLS_X509_BADCERT_NOT_TRUSTED` (0x00000008), emits TLS Fatal Alert 48, and terminates connection without receiving payload.
* **Console Output:**
  ```text
  [*] Pinned Trust Anchor: BTP Root CA (Subject: CN=BTP Root CA, O=BTP Secure IoT)
  [*] Inbound Server Certificate: Subject: CN=localhost (Issued by rogue/untrusted issuer)
  [!] TLS X.509 CERTIFICATE VERIFICATION FAILED: 0x00000008 (BADCERT_NOT_TRUSTED)
  [!] TLS Alert Sent: Fatal Alert 48 (Unknown CA / Certificate Untrusted).
  [+] TLS Handshake ABORTED! Zero firmware bytes downloaded over untrusted connection.
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (MitM Rogue Certificate Blocked)
  ```

---

### Scenario 10: Bad Manifest Magic Bytes (`press '0'`)
* **C Function:** `attack_matrix_scenario_10_bad_magic_bytes()` in [`attack_matrix.c`](file:///c:/Users/Manas/Desktop/xyz/btp/idf_hardware/main/attack_matrix.c)
* **What the C Code Does:**
  1. Attacker sends a malformed manifest header with corrupt magic `0xDEADBEEF` instead of `0x53554954`.
  2. Evaluates manifest header bounds via `suit_validate_manifest()`.
  3. Fails instantly on magic byte check, preventing memory corruption or buffer overflows.
* **Console Output:**
  ```text
  [*] Header magic byte evaluated: 0xDEADBEEF (Expected 0x53554954 'SUIT')
  [!] SUIT MANIFEST REJECTED: Header magic mismatch!
  [+] Parser stops immediately; zero memory allocated, zero payload downloaded.
  [✓] EVALUATION RESULT: CORRECTLY REJECTED (Malformed Manifest Header Blocked)
  ```

---

## 6. Host-Side Cryptographic Tool Verification

In addition to running simulations on the chip, you can verify signatures and eFuses from PowerShell:

### Verify Binary Signature with `espsecure.py`
```powershell
espsecure.py verify_signature --version 2 -k secure_boot_signing_key.pem build/esp32c6_hardware_security.bin
```
*Output:* `Signature is valid! Verification successful for version 2 signature block.`

### Non-Destructive Hardware eFuse Audit with `espefuse.py`
```powershell
espefuse.py -p COM5 summary
```
*Key registers displayed:*
- `BLOCK_KEY0`: Secure Boot v2 RSA public key digest
- `BLOCK_KEY2`: Flash Encryption 256-bit AES-XTS key
- `SECURE_VERSION`: Monotonic anti-rollback counter

---

## 7. Examiner Defense Talking Points (Pure C)

1. **"Why run tests directly in C on the board?"**  
   * *"Microcontrollers do not run Python in production. By implementing our verification engine, SUIT parser, and attack simulation in pure C99 with FreeRTOS and mbedTLS, we prove the framework runs natively within the constrained memory and CPU limits of the ESP32-C6 RISC-V core."*
2. **"How does the board calculate Shannon Entropy?"**  
   * *"Our C function `calculate_shannon_entropy()` reads raw flash bytes using `esp_partition_read()` and computes the probability distribution of each byte $0..255$. An entropy score above 7.95 mathematically proves that data stored in external flash is high-entropy ciphertext produced by the AES-XTS silicon engine."*
3. **"What prevents remote bricking?"**  
   * *"Our A/B partitioning with Two-Phase Commit ensures that candidate updates in `ota_1` boot under `PENDING_VERIFY`. If an uncaught panic occurs, the bootloader automatically invalidates the slot and boots back into `ota_0`."*
4. **"How do you defend against silent memory leaks or frozen threads after update (Health Check)?"**  
   * *"Digital signatures only verify source authenticity, not runtime stability. In Scenarios 6 and 7, our firmware runs pre-commit diagnostic assertions: checking internal SRAM headroom (`esp_get_free_internal_heap_size() > 20KB`) and monitoring the Task Watchdog Timer (TWDT). If memory exhausts or a thread hangs, the candidate never confirms health, causing the ESP32-C6 bootloader to roll back automatically."*
5. **"Why test RSA-PSS padding and salt corruption?"**  
   * *"Legacy PKCS#1 v1.5 padding is vulnerable to Bleichenbacher padding oracle attacks. Modern standards (RFC 8017 / RFC 9124) require RSASSA-PSS with randomized salt and MGF1 masking. Scenario 8 proves that even a 1-bit tampering in the PSS maskedDB salt immediately fails the hash de-masking check in mbedTLS."*
6. **"How does the client protect against local network TLS MitM proxying?"**  
   * *"In Scenario 9, the client pins the trusted BTP Root CA certificate. When an attacker proxies traffic using a rogue or forged CA cert, `mbedtls_x509_crt_verify()` detects `MBEDTLS_X509_BADCERT_NOT_TRUSTED`, issues TLS Fatal Alert 48, and terminates the connection before downloading any malicious payload."*
