# Complete Attack Matrix & Novelty Demonstrations (ESP32-C6)

This document details all security attack scenarios evaluated on the ESP32-C6 secure firmware update framework.
All attack scenarios must result in **CORRECTLY REJECTED** (except Test 1) for a passing security evaluation.

---

## 1. Complete Evaluator Attack Matrix

| # | Attack / Test Scenario | Threat Addressed | Execution Step / C Function | Expected Security Outcome | Status |
| :-: | :--- | :--- | :--- | :--- | :---: |
| **1** | **Valid Signed V2 Firmware** | Normal Operation | `attack_matrix_scenario_1_valid_signature()` | Authentic RSA + SHA-256 validated; candidate accepted. | **PASS** |
| **2** | **Modified V2 (Tampered Bytecode)** | MitM Payload Alteration | `attack_matrix_scenario_2_tampered_payload()` | Bit-flip in bytecode detected; hash mismatch aborts flash write. | **CORRECTLY REJECTED** |
| **3** | **Older Firmware (Rollback Attempt)** | Downgrade / CVE Replay | `attack_matrix_scenario_3_anti_rollback()` | Monotonic counter & silicon eFuses reject older sequence. | **CORRECTLY REJECTED** |
| **4** | **Flash Read Attempt (Cold-Boot/Bus Sniff)** | Physical Readout / IP Theft | `attack_matrix_scenario_4_flash_encryption_entropy()` | Hardware AES-XTS yields high-entropy (>7.95) pseudorandom ciphertext. | **CORRECTLY REJECTED** |
| **5** | **Crash-Loop / Faulty Firmware** | Bricking / Denial-of-Service | `attack_matrix_scenario_5_two_phase_commit()` | Probationary boot in `PENDING_VERIFY`; auto-reverts to Golden V1. | **CORRECTLY REJECTED** |
| **6** | **Health Check: Heap Exhaustion Attack** | Memory Starvation DoS | `attack_matrix_scenario_6_health_check_heap_starvation()` | Health check detects free heap < 20 KB; refuses commit and rolls back. | **CORRECTLY REJECTED** |
| **7** | **Health Check: Task Freeze / Watchdog Attack**| Service Deadlock DoS | `attack_matrix_scenario_7_health_check_watchdog_timeout()` | Deadlocked candidate misses probation heartbeat; TWDT resets & reverts. | **CORRECTLY REJECTED** |
| **8** | **RSA-PSS Padding & Salt Corruption Attack** | Cryptographic Exploit (RFC 8017)| `attack_matrix_scenario_8_rsa_pss_tampered_salt()` | Injected bit-flip in PSS maskedDB/salt caught by mbedTLS PSS engine. | **CORRECTLY REJECTED** |
| **9** | **HTTPS / TLS Rogue CA MitM Spoofing Attack** | Network Eavesdropping / Hijack | `attack_matrix_scenario_9_https_untrusted_ca_mitm()` | Pinned Root CA rejects unauthorized server cert (`BADCERT_NOT_TRUSTED`).| **CORRECTLY REJECTED** |
| **10**| **Bad Magic Header Bytes (`0xDEADBEEF`)** | Malformed / Rogue Binary | `attack_matrix_scenario_10_bad_magic_bytes()` | Header magic rejected at offset 0 before downloading single binary byte. | **CORRECTLY REJECTED** |
| **11**| **Unauthorized Device ID / Header Spoofing** | Rogue Node Impersonation | `server/ota_server.py` + mTLS check | Header spoofing blocked; strict client certificate validation enforced. | **CORRECTLY REJECTED** |

---

## 2. In-Depth Novelty Attack Breakdowns

### Novelty 1: Health Check Attacks & Two-Phase Commit Resilience
* **Why this matters to examiners:** Signatures only verify who built the firmware, not whether it is stable.
* **Attack Scenario A (Memory Starvation):**
  - Candidate V2 boots, but leaks memory leaving < 8 KB heap free.
  - The health check runs pre-commit diagnostics:
    ```c
    if (esp_get_free_internal_heap_size() < MIN_SAFE_HEAP_THRESHOLD) {
        esp_ota_mark_app_invalid_rollback_and_reboot();
    }
    ```
  - The candidate is permanently marked `INVALID` in `otadata`, and the bootloader falls back to `ota_0`.
* **Attack Scenario B (Task Deadlock):**
  - Candidate freezes during initialization.
  - Hardware Task Watchdog Timer (TWDT) trips at T+10 seconds.
  - On reboot, the bootloader recognizes the probation window was not confirmed and boots `ota_0`.

---

### Novelty 2: RSA-PSS Signature Verification (RFC 8017 / RFC 9124)
* **Why this matters to examiners:** RSA PKCS#1 v1.5 is prone to Bleichenbacher padding oracle attacks. Modern standards (IETF SUIT RFC 9124 and ESP32 Secure Boot v2) mandate **RSA-PSS** (Probabilistic Signature Scheme).
* **Attack Mechanism:**
  - In RSA-PSS, the encoded message is:
    $$EM = \text{maskedDB} \parallel H \parallel \text{0xBC}$$
  - The attacker alters 1 bit in the salt or maskedDB area.
  - The mbedTLS engine `mbedtls_rsa_rsassa_pss_verify_ext()` applies MGF1, unmasks DB, reconstructs the salt $s$, and checks:
    $$H' = \text{SHA256}(\text{padding} \parallel \text{digest} \parallel s)$$
  - Digest verification fails with error `-0x4280` (`MBEDTLS_ERR_RSA_VERIFY_FAILED`). The signature is rejected.

---

### Novelty 3: HTTPS Transport Security & Root CA Pinning
* **Why this matters to examiners:** Proves the firmware update pipeline is protected against active Man-in-the-Middle network attackers.
* **Attack Mechanism:**
  - An attacker poisons DNS or ARP on the local Wi-Fi and intercepts the HTTPS connection.
  - The attacker serves a fake TLS certificate issued by an unauthorized rogue CA.
  - The ESP32-C6 X.509 verification engine checks the certificate chain against our pinned **BTP Root CA**:
    ```c
    mbedtls_x509_crt_verify(&server_cert, &pinned_root_ca, NULL, NULL, &flags, NULL, NULL);
    ```
  - Verification fails with flag `MBEDTLS_X509_BADCERT_NOT_TRUSTED`.
  - The TLS connection is aborted before a single byte of firmware can be received.

---

### Novelty 4: Hardware eFuse Anti-Rollback vs Software Counter
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
