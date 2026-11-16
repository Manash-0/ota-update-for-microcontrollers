# Secure Firmware Updates for Constrained IoT Devices (ESP32-C6)

A hardware-anchored, fault-tolerant Over-The-Air (OTA) firmware update architecture engineered for constrained IoT devices. This project advances an earlier software-only prototype (ESP8266) to a production-grade, hardware-enforced security posture using the **Espressif ESP32-C6 (RISC-V)** microcontroller.

---

## 1. System Architecture

The framework operates on a **Defense-in-Depth** multi-tier security model:

```
+-------------------------------------------------------------------------------+
|                             OTA UPDATE SERVER                                 |
|  * HTTPS / TLS 1.2 & 1.3 Transport Encryption                                 |
|  * Mutual TLS (mTLS) Hardware Device Authentication (Anti-Spoofing)          |
|  * RFC 9124 SUIT Manifest Builder (CBOR + COSE-Sign1 RSA-2048 Signatures)    |
|  * Hash-Chained Append-Only Update Transparency Log                           |
+-------------------------------------------------------------------------------+
                                      |
                                      | HTTPS Stream (Pinned Root CA)
                                      v
+-------------------------------------------------------------------------------+
|                         ESP32-C6 SECURITY PLATFORM                            |
|                                                                               |
|  [Hardware Root of Trust]                                                     |
|  ├── Immutable ROM Bootloader                                                 |
|  ├── Secure Boot v2 (RSA Public Key Digest burned into eFuse)                |
|  ├── Hardware Flash Encryption Engine (AES-128/256-XTS)                       |
|  └── Hardware Anti-Rollback (Monotonic Silicon eFuse Security Version)        |
|                                                                               |
|  [Software Verification Engine]                                               |
|  ├── RFC 9124 SUIT Parser (Validates Magic 0x53554954, Class ID, Size)      |
|  ├── mbedTLS RSA-2048 PKCS#1 v1.5 Digital Signature Verification              |
|  ├── Streaming Hardware-Accelerated SHA-256 Digest Computation                |
|  └── Software Sequence Number Anti-Rollback Check                             |
|                                                                               |
|  [Fault-Tolerant Storage Engine]                                              |
|  ├── A/B Dual Partitioning (ota_0 = Golden V1, ota_1 = Candidate V2)          |
|  └── Two-Phase Commit Health Check (Auto-Rollback on Crash / Heap Exhaustion) |
+-------------------------------------------------------------------------------+
```

---

## 2. Two-Track Design

* **Track A (Arduino IDE 2.x):** Rapid prototyping, live demonstration, and application-layer security:
  * HTTPS OTA via `WiFiClientSecure` with Root CA certificate pinning
  * RFC 9124 SUIT manifest parsing (COSE-Sign1 envelope + JSON mirror)
  * Dual-partition flashing (`Update` API) with streaming SHA-256 integrity
  * Two-Phase Commit health check (`ESP_OTA_IMG_PENDING_VERIFY` -> `VALID` or rollback)
* **Track B (ESP-IDF 5.x Command-Line):** Silicon-level hardware root of trust:
  * Secure Boot v2 configuration (`sdkconfig.defaults`)
  * Hardware Flash Encryption in Development Mode
  * Immutable eFuse monotonic security version anti-rollback (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`)

---

## 3. Attack Matrix Evaluation Results

| # | Attack Scenario | Defense Layer | Expected Result | Evaluation Status |
| :-: | :--- | :--- | :--- | :---: |
| 1 | Valid Signed V2 Update | Complete Cryptographic Chain | Installs, passes health check, marked valid | **PASS** |
| 2 | Tampered V2 Binary (1 byte flipped) | SHA-256 & Secure Boot | Hash mismatch; flash write aborted | **CORRECTLY REJECTED** |
| 3 | Unsigned V2 Binary | SUIT / RSA-2048 Signature Check | Signature validation fails; update rejected | **CORRECTLY REJECTED** |
| 4 | Rollback Attempt (Older Firmware) | Monotonic Anti-Rollback Counter | Sequence number regression blocked | **CORRECTLY REJECTED** |
| 5 | Signed but Buggy V2 (Crash-loop) | Two-Phase Commit Health Check | Fails runtime test; auto-rollback to V1 | **CORRECTLY REJECTED** |
| 6 | SPI Flash Read / Bus Sniffing | Hardware Flash Encryption (AES) | High-entropy ciphertext extracted | **CORRECTLY REJECTED** |
| 7 | Corrupted Hash in Manifest | Streaming SHA-256 Engine | Digest mismatch at download completion | **CORRECTLY REJECTED** |
| 8 | Bad Header Magic (`0xDEADBEEF`) | SUIT Envelope Parser | Header rejected prior to binary download | **CORRECTLY REJECTED** |
| 9 | Unauthorized Device ID | Server-side Identity Allowlist | HTTP 403 Forbidden | **CORRECTLY REJECTED** |

---

## 4. Novelty Innovations (Project Highlights)

1. **Hardware eFuse vs Software Anti-Rollback:**
   * Demonstrates that software sequence numbers in flash/NVS can be bypassed by physical attackers wiping flash, whereas silicon eFuses are one-way physical links that permanently block downgrade attacks.
2. **Mutual TLS (mTLS) vs Header Spoofing:**
   * Proves that baseline `X-Device-ID` HTTP headers are trivially spoofed by any rogue client, while mTLS cryptographically binds requests to the device's private key.
3. **Real SUIT (RFC 9124) Manifest Parser:**
   * Complete implementation of IETF SUIT binary manifests using CBOR encoding and COSE-Sign1 structures parsed directly on the RISC-V core.
4. **Append-Only Update Transparency Ledger:**
   * Cryptographic hash-chained audit log preventing malicious or secret updates from being distributed undetected.

---

## 5. Performance Benchmarks Summary

* **TLS 1.2/1.3 Handshake:** **~310 ms** (ESP8266: ~1850 ms, **~5.9x faster**)
* **RSA-2048 Signature Verification:** **~22 ms** (ESP8266: ~145 ms, **~6.5x faster**)
* **SHA-256 DMA Hashing:** **~38.5 MB/s** (ESP8266: ~4.2 MB/s, **~9.1x faster**)
* **Boot Overhead under Secure Boot v2:** **+46 ms** (Total boot: ~88 ms)
* **OTA Transfer Speed:** **~71.4 KB/s** over WPA2 Wi-Fi
* **Internal SRAM Margin:** **>175 KB Free Heap** maintained during active TLS OTA streaming

---

## 6. Limitations & Future Work

* **ESP-TEE (Trusted Execution Environment):** Utilize the ESP32-C6 APM (Access Permission Management) hardware to run the OTA update client inside an isolated secure enclave.
* **Delta / Differential OTA:** Integrate `detools` / RFC 9124 delta compression to stream only binary diffs, reducing cellular/constrained IoT bandwidth by up to 80%.
* **Post-Quantum Cryptography (PQC):** Evaluate ML-DSA (Dilithium) and LMS/HSS stateful hash-based signatures for quantum-resistant firmware signing on constrained microcontrollers.

---

## 7. Slide-Ready Defense Bullets for Evaluators

* **Why Secure Boot?** OTA signatures only protect data over the network; Secure Boot anchors trust in hardware ROM every time the chip powers on.
* **Why A/B Partitions?** Eliminates bricking: updates stream into inactive slots, and pointers switch only after cryptographic validation succeeds.
* **Why Health Checks?** Distinguishes *authenticity* (is it signed?) from *usability* (does it crash?). A crashed candidate triggers immediate automatic rollback.
* **Why ESP32-C6?** Provides hardware cryptographic accelerators (AES-XTS, RSA, SHA), modern RISC-V architecture, and eFuses, overcoming all physical limitations of the ESP8266.

