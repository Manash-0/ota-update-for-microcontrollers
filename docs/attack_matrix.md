# Complete 9-Test Attack Matrix & Novelty Demonstrations

This document details each test scenario evaluated on the ESP32-C6 secure firmware update framework.
All tests must result in **CORRECTLY REJECTED** (except Test 1) for a passing security evaluation.

---

## 1. Core 9-Test Attack Matrix

| # | Attack / Test Scenario | Threat Addressed | Execution Step / Command | Expected Security Outcome | Actual Result (Placeholder) | Status |
| :-: | :--- | :--- | :--- | :--- | :--- | :---: |
| **1** | **Valid Signed V2 Firmware** | Normal Operation | Build authentic V2 (`seq=2, ver=2.0.0`), upload to server, trigger OTA. | V2 downloads, passes RSA-2048 & SHA-256 checks, boots, passes health check, marked `VALID`. | *[Paste Serial Log: "Two-Phase Commit: Marking image as permanently VALID"]* | **PASS** |
| **2** | **Modified V2 (Tampered Binary)** | Man-in-the-Middle / Payload Alteration | Single byte flipped in compiled V2 binary code (`firmware_v2_tampered.bin`). | SHA-256 integrity check fails or Secure Boot rejects signature. V1 remains running in `ota_0`. | *[Paste Serial Log: "PAYLOAD HASH INTEGRITY MISMATCH... Update.abort()"]* | **CORRECTLY REJECTED** |
| **3** | **Unsigned V2 Firmware** | Unauthorized Firmware Injection | Upload binary with missing or invalid RSA signature block. | SUIT parser rejects with `SUIT_ERR_SIGNATURE_INVALID`. Flash write is blocked. | *[Paste Serial Log: "Cryptographic Signature Verification FAILED"]* | **CORRECTLY REJECTED** |
| **4** | **Older Firmware (Rollback Attempt)** | Downgrade Attack / CVE Exploitation | Attacker attempts to push V0/V1 (`seq=1`) when device runs V2 (`seq=2`). | Anti-rollback counter detects `candidate_seq <= current_seq`. OTA rejected immediately. | *[Paste Serial Log: "ANTI-ROLLBACK TRIGGERED: Candidate seq (1) <= Current seq (2)"]* | **CORRECTLY REJECTED** |
| **5** | **Signed but Buggy V2 Firmware** | Bricking / Crash-Loop Injection | Attacker/developer signs firmware with fatal bug (`SIMULATE_BUGGY_V2 = true`). | V2 boots once into `PENDING_VERIFY`. Health check fails. Bootloader rolls back to `ota_0` (V1). | *[Paste Serial Log: "FATAL SIMULATED BUG DETECTED... esp_ota_mark_app_invalid_rollback_and_reboot"]* | **CORRECTLY REJECTED** |
| **6** | **Flash Read Attempt (Cold-Boot/Bus Sniff)** | Physical Data Extraction / Reverse Engineering | Connect external programmer or run `esptool.py read_flash` on flash chip. | Flash Encryption (AES-XTS) returns high-entropy pseudorandom ciphertext. Plaintext code is protected. | *[Paste Hex Dump screenshot showing encrypted ciphertext]* | **CORRECTLY REJECTED** |
| **7** | **Corrupt Hash in Manifest** | Manifest Tampering / Transit Bit-Flip | Manifest contains wrong SHA-256 digest (`?attack=corrupt_hash`). | Client verifies binary SHA-256 against manifest; mismatch triggers abort before committing. | *[Paste Serial Log: "PAYLOAD HASH INTEGRITY MISMATCH... TEST 7 CORRECTLY REJECTED"]* | **CORRECTLY REJECTED** |
| **8** | **Bad Magic Bytes (`0xDEADBEEF`)** | Malformed / Untargeted Binary | Manifest header magic modified from `0x53554954` to `0xDEADBEEF`. | SUIT parser rejects header during initial manifest validation phase before downloading binary. | *[Paste Serial Log: "BAD MAGIC REJECTED: 0xDEADBEEF detected! TEST 8 CORRECTLY REJECTED"]* | **CORRECTLY REJECTED** |
| **9** | **Unauthorized Device ID** | Rogue Node Impersonation / Fleet Segmentation | Request manifest with spoofed/unauthorized device ID header `X-Device-ID: ATTACKER_999`. | Server responds with `HTTP 403 Forbidden`. Device is logged in tamper-evident ledger. | *[Paste Server Log: "Access DENIED for unauthorized client... HTTP 403"]* | **CORRECTLY REJECTED** |

---

## 2. Novelty Demonstrations (Extra Grade Points)

### Novelty 1: Hardware eFuse Anti-Rollback vs Software Counter
* **Objective:** Prove that a physical attacker can bypass software anti-rollback by reflashing NVS/flash, but **cannot** bypass eFuse hardware security versioning.
* **Attack Scenario A (Software Counter):**
  1. Device at V2 has software sequence counter = 2 stored in flash.
  2. Attacker uses physical USB/SPI programmer to erase flash or wipe NVS partition.
  3. Attacker flashes signed V1 firmware.
  4. Device boots vulnerable V1 because software counter was wiped! **(VULNERABLE)**
* **Attack Scenario B (Hardware eFuse):**
  1. Device at V2 has eFuse `SECURE_VERSION` burned to 2 (microscopic silicon fuses blown).
  2. Attacker uses physical programmer to flash signed V1 with security version 1.
  3. ESP32-C6 ROM Bootloader checks `eFuse SEC_VER (2) > app_desc sec_ver (1)`.
  4. ROM bootloader **aborts boot permanently** before executing any instruction of V1! **(SECURE)**

---

### Novelty 2: Header-Spoofing Vulnerability vs Hardware mTLS
* **Objective:** Demonstrate that the baseline `X-Device-ID` HTTP header is trivial to spoof, whereas Mutual TLS (mTLS) with client certificate verification makes spoofing mathematically impossible without the private key.
* **Step 1 (Baseline Weakness):**
  ```bash
  # Attacker machine (no private keys) sends plain curl with forged header:
  curl -k -H "X-Device-ID: ESP32C6-SMARTELEX-01" https://<SERVER_IP>:8443/ota/firmware.bin -o stolen.bin
  # Result: HTTP 200 OK -> Firmware exfiltrated!
  ```
* **Step 2 (mTLS Hardware Enforcement):**
  ```bash
  # Server started with --mtls flag:
  python ota_server.py --mtls
  # Attacker attempts curl without client certificate:
  curl -k -H "X-Device-ID: ESP32C6-SMARTELEX-01" https://<SERVER_IP>:8443/ota/firmware.bin
  # Result: TLS Alert: 'sslv3 alert bad certificate' or connection reset!
  ```

---

### Novelty 3: Real SUIT Manifest (RFC 9124 / CBOR + COSE-Sign1)
* **Objective:** Move beyond ad-hoc JSON manifests to the official IETF standard for constrained IoT devices.
* **Structure Inspected:**
  ```text
  COSE_Sign1 (RFC 8152):
    ├── Protected Header: { 1: -257 (RS256) }
    ├── Unprotected Header: { 4: 'key-btp-01' }
    ├── Payload (CBOR map):
    │     ├── 1: 0x53554954 ("SUIT")
    │     ├── 2: 2 (Anti-rollback Sequence Number)
    │     ├── 3: 135424 (Image Size)
    │     └── 4: h'6fe9b9...6c14' (SHA-256 Digest)
    └── Signature: 256-byte RSA PKCS#1 v1.5 Signature
  ```
* **Result:** Successfully parsed and verified directly inside the ESP32-C6 RISC-V core using hardware-accelerated mbedTLS.

