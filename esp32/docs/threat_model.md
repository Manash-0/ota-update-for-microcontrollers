# Threat Model: Secure OTA Firmware Updates for ESP32-C6

## 1. System Overview
The Target of Evaluation (TOE) is a constrained IoT node based on the Espressif ESP32-C6 (RISC-V 32-bit single-core, 160 MHz, 4 MB SPI Flash, Wi-Fi 6 / 802.15.4 / BLE 5) receiving Over-The-Air (OTA) firmware binaries over untrusted IP networks.

---

## 2. STRIDE Threat Analysis & Defense Mapping

| Threat Category | Specific Threat Scenario | Impact | Baseline (ESP8266) Limitation | ESP32-C6 Defense Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates the OTA Update Server via DNS spoofing / ARP poison. | Device downloads malicious binary from rogue host. | Plain HTTP without cert validation allowed MitM attacks. | **Transport Layer Security (TLS 1.2/1.3)** with pre-provisioned CA certificate pinning. |
| **Spoofing** | Attacker spoofs `X-Device-ID` HTTP header to download restricted firmware. | Device masquerades as authorized fleet unit. | HTTP headers are easily forged in transit. | **Mutual TLS (mTLS)**: Device authenticates with hardware-protected private key. |
| **Tampering** | Man-in-the-Middle alters binary payload in transit or on flash storage. | Arbitrary code execution; botnet recruitment. | Software SHA-256 only protects transit, not flash. | **SUIT / COSE-Sign1 Digital Signatures (RSA-2048/SHA-256)** + **Secure Boot v2** hardware verification on boot. |
| **Tampering** | Physical attacker connects logic analyzer to external SPI flash pins. | Extracts firmware secrets or writes malicious bytecode directly. | ESP8266 flash pins expose plaintext data and code. | **Hardware Flash Encryption (AES-128/256-XTS)** via eFuse key. Extracted flash reads as high-entropy ciphertext. |
| **Repudiation** | Rogue vendor pushes malicious build and denies authorship. | Inability to audit supply-chain compromises. | Centralized server logs can be scrubbed. | **Append-Only Update Transparency Log** with SHA-256 cryptographic hash-chaining. |
| **Information Disclosure** | Passive eavesdropping on local Wi-Fi or transit ISP. | Proprietary firmware reverse engineered. | Plaintext HTTP OTA exposed raw `.bin` files. | **HTTPS/TLS Transport Encryption** + Flash Encryption at rest. |
| **Denial of Service** | Flash write interrupted mid-transfer (power-loss / reset). | Device enters permanent bricked boot-loop. | Single-slot OTA bricked if corrupted midway. | **A/B Dual Partitioning (`ota_0`, `ota_1`)** with atomic bootloader pointer switching. |
| **Denial of Service** | Buggy validly-signed firmware crashes right after boot. | Unrecoverable remote field failure. | No automated rollback if firmware crashed post-boot. | **Health Check & Two-Phase Commit**: Bootloader marks new slot `ESP_OTA_IMG_PENDING_VERIFY`; rolls back to known-good if crash/timeout occurs. |
| **Elevation of Privilege** | Replay of valid, signed, older firmware with known CVEs (Rollback). | Device downgraded to vulnerable build. | Software sequence counter can be cleared via physical flash write. | **Dual Anti-Rollback**: Software SUIT sequence counter + **eFuse Hardware Monotonic Anti-Rollback (`SECURE_BOOT_ANTI_ROLLBACK`)**. |

---

## 3. Trust Boundaries & Attack Vectors

```
+-------------------------------------------------------------------+
|                        UNTRUSTED NETWORK                         |
|   Attacker Capabilities: Eavesdrop, Inject, Modify, Replay        |
+-------------------------------------------------------------------+
                               |  TLS 1.2/1.3 + mTLS
                               v
+-------------------------------------------------------------------+
|                       ESP32-C6 SOC BOUNDARY                       |
|                                                                   |
|  +--------------------+        +-------------------------------+  |
|  | Hardware eFuses    |        | Cryptographic Accelerators    |  |
|  | - Secure Boot Digest|       | - SHA-256 Hardware Engine     |  |
|  | - Flash Encrypt Key|        | - RSA-3072 / 2048 Engine      |  |
|  | - Anti-Rollback Ver|        | - AES Hardware Block          |  |
|  +--------------------+        +-------------------------------+  |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  | ROM Bootloader (Immutable Root of Trust)                   |  |
|  +-------------------------------------------------------------+  |
|                               | Verifies Signature                |
|                               v                                   |
|  +-------------------------------------------------------------+  |
|  | 2nd Stage Bootloader (Verifies App & Anti-Rollback)         |  |
|  +-------------------------------------------------------------+  |
|                               | Verifies A/B State                |
|                               v                                   |
|  +-----------------------------+ +-----------------------------+  |
|  | ota_0 (V1 Known Good)       | | ota_1 (V2 Candidate)        |  |
|  | Status: VALIDATED           | | Status: PENDING HEALTH CHECK|  |
|  +-----------------------------+ +-----------------------------+  |
+-------------------------------------------------------------------+
                               | SPI Bus (Encrypted by hardware)
                               v
               [ External 4 MB SPI Flash Memory ]
```

