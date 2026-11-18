# Final B.Tech Review Presentation Outline & Evaluation Defense Guide

This document maps the project directly to your evaluation slide deck, provides a 5-minute live demo script, prepares you for rigorous examiner cross-examination, and provides updated slide text.

---

## 1. Slide-by-Slide Repository & Demo Mapping

| Slide # | Slide Title | Corresponding Repo File | Live Demo Moment / Visual Artifact |
| :---: | :--- | :--- | :--- |
| **1** | Title & Team | `README.md` | Introduce project title, role, and problem scope. |
| **2** | Problem Statement & Objective | `docs/threat_model.md` | Point out firmware tampering, bricking risk, and rollback exploits in IoT. |
| **3** | Evolution: ESP8266 to ESP32-C6 | `docs/benchmarks.md` | Show architecture comparison table (Software-only vs Hardware-backed). |
| **4** | End-to-End Architecture | `arduino/ota_client/` | Architectural block diagram: Server -> TLS -> SUIT Parser -> Dual A/B. |
| **5** | SUIT Manifest & Cryptography | `server/build_manifest.py` | Highlight RFC 9124 CBOR + COSE-Sign1 structure and RSA-2048 signing. |
| **6** | Hardware Security Engines | `idf_hardware/` | Secure Boot v2, Flash Encryption (AES-XTS), and eFuse anti-rollback. |
| **7** | Two-Phase Commit & Rollback | `arduino/ota_client/health_check.cpp` | Explain `PENDING_VERIFY` state machine and automated recovery. |
| **8** | Novelty: eFuse vs Software Anti-Rollback | `docs/attack_matrix.md` | **Demo:** Explain why physical flash wipe resets software counter but cannot reset eFuses. |
| **9** | Novelty: Spoofable Header vs mTLS | `tests/run_attack_matrix.py` | **Demo:** Show attacker exfiltrating firmware with forged header; blocked when mTLS on. |
| **10**| Attack Matrix (10 Tests in Pure C) | `docs/attack_matrix.md`, `idf_hardware/main/` | Display 10/10 PASS / CORRECTLY REJECTED evaluation scorecard: Health Check Heap & Watchdog, RSA-PSS, HTTPS MitM. |
| **11**| Performance Benchmarks | `docs/benchmarks.md` | Present TLS handshake timing, RSA speedup (~6.5x), and flash overhead. |
| **12**| Conclusion & Future Work | `README.md` | Summarize contributions, ESP-TEE roadmap, and delta updates. |

---

## 2. Five-Minute Live Demo Script (Pure C Interactive Console)

* **[0:00 - 0:45] Setup & Hardware Trust Anchors:**
  - "Respected evaluators, here is our Smartelex ESP32-C6 running native C firmware under ESP-IDF."
  - Point to Serial Monitor:
    ```text
    [+] Secure Boot v2: ACTIVE & ENFORCED IN HARDWARE
    [+] Hardware Flash Encryption: ACTIVE (Development Mode)
    [*] App Secure Version: 1
    [*] Booted Partition: 'ota_0' @ 0x00010000 (1792 KB)
    ```
  - "Everything running on the chip is 100% pure C using FreeRTOS, ESP-IDF OTA APIs, and hardware mbedTLS."

* **[0:45 - 2:00] Cryptographic & Manifest Attacks (Scenarios 1, 2, 8, 10):**
  - "We built an interactive on-chip test suite to simulate attacks right before your eyes:
    1. **Press '1':** Computes hardware SHA-256 and validates genuine SUIT manifest -> `PASS`.
    2. **Press '2':** Attacker inverts 1 byte in payload -> Detected by SHA-256 engine -> `CORRECTLY REJECTED`.
    3. **Press '8':** Attacker flips 1 bit in RSA-PSS salt/padding -> `mbedtls_rsa_rsassa_pss_verify_ext()` fails -> `CORRECTLY REJECTED`.
    4. **Press '0':** Malformed header magic `0xDEADBEEF` -> Parser drops header instantly."

* **[2:00 - 3:15] Hardware Security: Flash Encryption & Anti-Rollback (Scenarios 3, 4):**
  - "Now, physical and downgrade attacks:
    1. **Press '3' (Anti-Rollback):** Attacker replays older signed firmware (seq 1). Both software counter AND silicon eFuse `SECURE_VERSION` block rollback -> `CORRECTLY REJECTED`.
    2. **Press '4' (Flash Snooping & Entropy):** Board reads raw SPI flash bytes and computes Shannon Entropy live via `calculate_shannon_entropy()`. Output: **7.9569 / 8.0000** (AES-XTS ciphertext, zero plaintext code on SPI bus)."

* **[3:15 - 4:15] Runtime Resilience: Health Checks & HTTPS MitM (Scenarios 5, 6, 7, 9):**
  - "What if firmware is authentically signed by manufacturer, but has bugs or the network is hostile?
    1. **Press '6' (Heap Exhaustion):** Firmware detects free SRAM drops below 20 KB -> Refuses commit and triggers `esp_ota_mark_app_invalid_rollback_and_reboot()`.
    2. **Press '7' (Task Hang / Watchdog):** Candidate task freezes -> Task Watchdog Timer (TWDT) resets CPU -> Bootloader rolls back to Golden V1.
    3. **Press '9' (HTTPS Rogue CA MitM):** Untrusted certificate proxy detected by pinned root CA -> Emits TLS Fatal Alert 48 and drops connection."

* **[4:15 - 5:00] Summary & Benchmarks:**
  - Display the benchmark comparison table: 6.5x faster crypto than ESP8266, zero-brick guarantee, true hardware root of trust.

---

## 3. High-Probability Evaluator Questions & Defenses

### Q1: "Why do we need Secure Boot if we already verify RSA digital signatures during OTA?"
* **Answer:** "Digital signature verification in the OTA client only protects against corrupted binaries arriving *over the network*. However, if an attacker has physical access to the device or uses an external SPI flash programmer, they can flash arbitrary code directly onto the flash chip, completely bypassing the software OTA client. **Secure Boot v2** enforces the root of trust inside the read-only hardware ROM bootloader. Every time the ESP32-C6 powers on or resets, the ROM bootloader cryptographically verifies the signature before the CPU executes a single instruction."

### Q2: "What happens if candidate firmware is authentically signed but causes memory leaks or freezes?"
* **Answer:** "Signature verification proves origin authenticity, not software correctness. This is why we engineered a **Two-Phase Commit Health Check**. When new firmware boots for the first time, it enters probationary state `ESP_OTA_IMG_PENDING_VERIFY`. Our diagnostic self-tests verify that internal SRAM remains above our 20 KB safety margin and that all FreeRTOS task heartbeats pet the Task Watchdog Timer (TWDT). If memory starves or a task freezes, the bootloader automatically marks the candidate invalid in the `otadata` ledger and reverts to Golden V1."

### Q3: "Why test RSA-PSS padding corruption instead of only legacy PKCS#1 v1.5?"
* **Answer:** "Standard PKCS#1 v1.5 padding is deterministic and vulnerable to Bleichenbacher padding oracle attacks. Modern standards (RFC 8017 and IETF SUIT RFC 9124) require RSASSA-PSS, which uses randomized salt, MGF1 mask generation, and fixed trailer bytes. In Scenario 8, we verify that flipping even a single bit in the PSS maskedDB salt causes `mbedtls_rsa_rsassa_pss_verify_ext()` to reject the signature immediately."

### Q4: "What if TLS encryption is compromised or a rogue CA issues a fake server cert?"
* **Answer:** "First, we employ **Root CA Certificate Pinning** directly in the firmware (`mbedtls_x509_crt_verify()`), which detects and rejects rogue CAs with `MBEDTLS_X509_BADCERT_NOT_TRUSTED` and TLS Fatal Alert 48. Second, we follow the principle of **Defense-in-Depth**: even if TLS transport were completely broken by an active adversary, the firmware binary is wrapped in an RFC 9124 SUIT envelope containing an independent RSA digital signature. The attacker cannot forge the manufacturer's private firmware signing key, so the payload is rejected."

### Q5: "What happens if power is abruptly lost midway through writing the OTA update?"
* **Answer:** "Because we use **A/B Dual Partitioning**, the actively executing firmware resides in `ota_0`. The new candidate firmware is written exclusively into the inactive partition `ota_1`. The bootloader pointer in the `otadata` partition is only updated atomically *after* the entire download is complete and the full SHA-256 hash matches. If power is pulled at 50% download, the bootloader continues booting `ota_0` safely upon power restoration. It is physically impossible to brick the device via partial writes."

### Q6: "Why did you transition from ESP8266 to ESP32-C6?"
* **Answer:** "The ESP8266 is fundamentally incapable of hardware security: it lacks hardware cryptographic accelerators, has no Secure Boot ROM, has no flash encryption (exposing code and keys on the SPI bus), and has no eFuses for monotonic anti-rollback. The ESP32-C6 provides a modern RISC-V core with dedicated hardware engines for AES-XTS, RSA-3072, and SHA-256, allowing full HTTPS and digital signature checks with minimal latency (~300 ms vs ~2 s on ESP8266)."

---

## 4. Fallback Plan (If Live Hardware / Network Glitches)
* Keep `results/` populated with:
  1. Complete serial monitor logs of successful V1 -> V2 OTA.
  2. Screenshots of the 9-test attack matrix terminal output (`run_attack_matrix.py`).
  3. Pre-recorded 60-second video clip of the board booting and rolling back.

---

## 5. Updated Slide Text for LaTeX Presentation

### Slide: Hardware & Software Setup (Updated for ESP32-C6)
```latex
\begin{frame}{Hardware \& Software Setup}
\begin{columns}[T]
\column{0.48\textwidth}
\begin{block}{Hardware}
\small
\begin{tabular}{l l}
\toprule
\textbf{Spec} & \textbf{Detail} \\
\midrule
MCU & Espressif ESP32-C6 (Pico Dev Board) \\
CPU & 32-bit RISC-V (RV32IMAC) @ 160\,MHz \\
Flash & 4\,MB SPI Flash (AES-XTS Encrypted) \\
Security & Secure Boot v2, eFuse Monotonic Anti-Rollback \\
Network & Wi-Fi 6 (802.11ax), BLE 5.3, 802.15.4 \\
\bottomrule
\end{tabular}
\end{block}

\column{0.48\textwidth}
\begin{block}{Software Stack}
\small
\begin{tabular}{l l}
\toprule
\textbf{Layer} & \textbf{Technology} \\
\midrule
Server & Python HTTPS Server + mTLS + Hash Log \\
Transport & TLS 1.2 / TLS 1.3 with CA Pinning \\
Manifest & RFC 9124 SUIT (CBOR + COSE-Sign1) \\
Signatures & RSA-2048 (PKCS\#1 v1.5 / SHA-256) \\
Storage & A/B Dual Partition with Two-Phase Commit \\
\bottomrule
\end{tabular}
\end{block}
\end{columns}
\end{frame}
```

