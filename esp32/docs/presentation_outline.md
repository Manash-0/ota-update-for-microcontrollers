# Final B.Tech Review Presentation Outline & Evaluation Defense Guide

This document maps the project directly to your evaluation slide deck, provides a 5-minute live demo script, prepares you for rigorous examiner cross-examination, and provides updated slide text.

---

## 1. Slide-by-Slide Repository & Demo Mapping

| Slide # | Slide Title | Corresponding Repo File | Live Demo Moment / Visual Artifact |
| :---: | :--- | :--- | :--- |
| **1** | Title & Team | `README.md` | Introduce project title, role, and problem scope. |
| **2** | Problem Statement & Objective | `docs/threat_model.md` | Point out firmware tampering, bricking risk, and rollback exploits in IoT. |
| **3** | Evolution: ESP8266 to ESP32-C6 | `docs/benchmarks.md` | Show architecture comparison table (Software-only vs Hardware-backed). |
| **4** | End-to-End Architecture | `esp32/arduino/ota_client/` | Architectural block diagram: Server -> TLS -> SUIT Parser -> Dual A/B. |
| **5** | SUIT Manifest & Cryptography | `esp32/server/build_manifest.py` | Highlight RFC 9124 CBOR + COSE-Sign1 structure and RSA-2048 signing. |
| **6** | Hardware Security Engines | `esp32/idf_hardware/` | Secure Boot v2, Flash Encryption (AES-XTS), and eFuse anti-rollback. |
| **7** | Two-Phase Commit & Rollback | `esp32/arduino/ota_client/health_check.cpp` | Explain `PENDING_VERIFY` state machine and automated recovery. |
| **8** | Novelty: eFuse vs Software Anti-Rollback | `docs/attack_matrix.md` | **Demo:** Explain why physical flash wipe resets software counter but cannot reset eFuses. |
| **9** | Novelty: Spoofable Header vs mTLS | `esp32/tests/run_attack_matrix.py` | **Demo:** Show attacker exfiltrating firmware with forged header; blocked when mTLS on. |
| **10**| Attack Matrix (9 Tests) | `docs/attack_matrix.md` | Display 9/9 PASS / CORRECTLY REJECTED evaluation scorecard. |
| **11**| Performance Benchmarks | `docs/benchmarks.md` | Present TLS handshake timing, RSA speedup (~6.5x), and flash overhead. |
| **12**| Conclusion & Future Work | `README.md` | Summarize contributions, ESP-TEE roadmap, and delta updates. |

---

## 2. Five-Minute Live Demo Script

* **[0:00 - 0:45] Setup & Initial State (V1):**
  - "Respected evaluators, here is our Smartelex ESP32-C6 running baseline V1 firmware in partition `ota_0`."
  - Point to Serial Monitor: `Firmware Version: 1.0.0, Running Partition: ota_0`.
  - Point to local server: `ota_server.py` listening on port 8443 with append-only transparency ledger.

* **[0:45 - 2:00] Live Authentic Update (V1 -> V2) & Two-Phase Commit:**
  - "Now, we push genuine V2 firmware (`seq=2`). I press 'u' to trigger the update."
  - Walk through logs as they stream:
    1. TLS 1.3 handshake completed in 310 ms.
    2. SUIT Manifest fetched; RSA-2048 signature validated against embedded public key.
    3. Binary streamed into `ota_1`; streaming SHA-256 matches manifest digest.
    4. Device reboots into candidate slot `ota_1`.
    5. Health check runs: `PENDING_VERIFY` -> Heap verified -> Permanently marked `VALID`.

* **[2:00 - 3:15] Attack Matrix Demos (Tampering & Anti-Rollback):**
  - "Now, let's attack the system:
    1. **Rollback Attack (Test 4):** Attacker pushes old firmware with sequence 1. Serial shows: `ANTI-ROLLBACK TRIGGERED: Candidate seq (1) <= Current seq (2)`.
    2. **Tampered Payload (Test 2):** Single byte flipped in binary. Serial shows: `PAYLOAD HASH INTEGRITY MISMATCH... Update.abort()`.
    3. **Bad Magic (Test 8):** Injected `0xDEADBEEF` rejected instantly at manifest phase."

* **[3:15 - 4:15] Novelty Demos (mTLS & Buggy V2 Rollback):**
  - **Header Spoofing vs mTLS:** Run `python run_attack_matrix.py` in terminal. Show that an unauthorized curl command is rejected under mTLS.
  - **Buggy Firmware Recovery (Test 5):** "What if firmware is signed but crashes? Watch the board boot the buggy build, detect the failure during health check, and automatically fall back to known-good V1 without human intervention!"

* **[4:15 - 5:00] Summary & Benchmarks:**
  - Display the benchmark comparison table: 6.5x faster crypto than ESP8266, zero-brick guarantee, true hardware root of trust.

---

## 3. High-Probability Evaluator Questions & Defenses

### Q1: "Why do we need Secure Boot if we already verify RSA digital signatures during OTA?"
* **Answer:** "Digital signature verification in the OTA client only protects against corrupted binaries arriving *over the network*. However, if an attacker has physical access to the device or uses an external SPI flash programmer, they can flash arbitrary code directly onto the flash chip, completely bypassing the software OTA client. **Secure Boot v2** enforces the root of trust inside the read-only hardware ROM bootloader. Every time the ESP32-C6 powers on or resets, the ROM bootloader cryptographically verifies the signature before the CPU executes a single instruction."

### Q2: "What happens if power is abruptly lost midway through writing the OTA update?"
* **Answer:** "Because we use **A/B Dual Partitioning**, the actively executing firmware resides in `ota_0`. The new candidate firmware is written exclusively into the inactive partition `ota_1`. The bootloader pointer in the `otadata` partition is only updated atomically *after* the entire download is complete and the full SHA-256 hash matches. If power is pulled at 50% download, the bootloader continues booting `ota_0` safely upon power restoration. It is physically impossible to brick the device via partial writes."

### Q3: "What if TLS encryption is compromised or a rogue CA issues a fake server cert?"
* **Answer:** "First, we employ **Root CA Certificate Pinning** directly in the firmware, rejecting any untrusted certificate authorities. Second, we follow the principle of **Defense-in-Depth**: even if TLS transport were completely broken by an active adversary, the firmware binary is wrapped in an RFC 9124 SUIT envelope containing an independent RSA-2048 digital signature. The attacker cannot forge the manufacturer's private firmware signing key, so the payload is rejected."

### Q4: "Why did you transition from ESP8266 to ESP32-C6?"
* **Answer:** "The ESP8266 is fundamentally incapable of hardware security: it lacks hardware cryptographic accelerators, has no Secure Boot ROM, has no flash encryption (exposing code and keys on the SPI bus), and has no eFuses for monotonic anti-rollback. The ESP32-C6 provides a modern RISC-V core with dedicated hardware engines for AES-XTS, RSA-3072, and SHA-256, allowing full HTTPS and digital signature checks with minimal latency (~300 ms vs ~2 s on ESP8266)."

---

## 4. Fallback Plan (If Live Hardware / Network Glitches)
* Keep `esp32/results/` populated with:
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

