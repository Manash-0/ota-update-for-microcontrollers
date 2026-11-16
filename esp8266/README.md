# Secure Firmware Updates for Constrained IoT Devices

> **Paper:** *"Secure Firmware Updates for Constrained IoT Devices using Open Standards"*  
> **Hardware:** NodeMCU 1.0 (ESP-12E) — ESP8266  
> **Server:** Node.js (zero dependencies)  
> **Desktop Simulation:** C++17

---

## 📌 Objective

Design and implement a **secure Over-The-Air (OTA) firmware update framework** for resource-constrained IoT devices. The system ensures that only authentic, untampered, and version-compliant firmware can be installed on target devices — protecting against supply-chain attacks, rollback exploits, and unauthorized modifications.

## 🎯 Goal

| # | Goal | Status |
|---|------|--------|
| 1 | Implement SUIT-compliant manifest parsing on a real microcontroller | ✅ |
| 2 | Enforce SHA-256 integrity verification of firmware images | ✅ |
| 3 | Validate ed25519 digital signatures (trust anchor) | ✅ |
| 4 | Prevent rollback attacks via monotonic sequence numbers | ✅ |
| 5 | Authorize devices before serving firmware (X-Device-ID) | ✅ |
| 6 | Demonstrate 6 edge-case security attack scenarios | ✅ |
| 7 | Provide a desktop C++ simulation with dual-slot bootloader | ✅ |
| 8 | Build a zero-dependency Node.js update server with dashboard | ✅ |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      MOBILE HOTSPOT (2.4 GHz WiFi)              │
│                                                                  │
│   ┌───────────────────┐          ┌────────────────────────────┐  │
│   │   💻 LAPTOP        │  HTTP    │  📟 NodeMCU ESP-12E        │  │
│   │   Node.js Server  │◄────────►│  OTA Client (ESP8266)     │  │
│   │   Port 8082       │          │  80 MHz, 4MB Flash        │  │
│   │                   │          │  BearSSL Crypto Engine    │  │
│   │  ┌─────────────┐  │          │                            │  │
│   │  │ SUIT Manifest│  │          │  ┌──────────────────────┐  │  │
│   │  │ Builder      │  │          │  │ SUIT Manifest Parser │  │  │
│   │  ├─────────────┤  │          │  ├──────────────────────┤  │  │
│   │  │ Firmware     │  │          │  │ SHA-256 Verifier     │  │  │
│   │  │ Store        │  │          │  ├──────────────────────┤  │  │
│   │  ├─────────────┤  │          │  │ ed25519 Signature    │  │  │
│   │  │ Edge-Case    │  │          │  ├──────────────────────┤  │  │
│   │  │ Test Suite   │  │          │  │ Anti-Rollback Engine │  │  │
│   │  ├─────────────┤  │          │  ├──────────────────────┤  │  │
│   │  │ Device Auth  │  │          │  │ OTA Flash Writer     │  │  │
│   │  │ (X-Device-ID)│  │          │  └──────────────────────┘  │  │
│   │  └─────────────┘  │          └────────────────────────────┘  │
│   └───────────────────┘                                          │
└──────────────────────────────────────────────────────────────────┘
```

### Three-Tier Architecture

| Tier | Component | Role |
|------|-----------|------|
| **Tier 1** | Mobile Hotspot | 2.4 GHz WiFi network connecting laptop and ESP8266 |
| **Tier 2** | Node.js Server (Laptop) | Builds SUIT manifests, serves firmware, runs edge-case test endpoints |
| **Tier 3** | ESP8266 OTA Client | Fetches manifest, validates security, downloads firmware, applies OTA |

---

## 🔄 Architecture Flow

```
  ┌─────────┐       ┌───────────────┐       ┌───────────────┐
  │ Author  │──────►│ Update Server │──────►│  IoT Device   │
  │ (Build) │ signs │  (Node.js)    │ serves│  (ESP8266)    │
  └─────────┘       └───────────────┘       └───────────────┘
       │                    │                       │
   Compile FW         Store manifest          WiFi Connect
       │              + FW binary                   │
   Sign with              │                   Fetch manifest
   ed25519 key             │                       │
       │                    │                 Parse SUIT fields
   Compute              Serve via              (magic, seq,
   SHA-256              HTTP GET               uri, hash, sig)
       │                    │                       │
   Build SUIT          Validate              Verify signature
   manifest            Device-ID             (trust anchor)
       │                    │                       │
       └─────── Package ────┘                 Anti-rollback
                                              check (seq > current)
                                                    │
                                              Download firmware
                                                    │
                                              SHA-256 verify
                                              (computed vs manifest)
                                                    │
                                              Apply OTA update
                                              (write to flash)
```

---

## 📋 Process Flow (9-Step Update Pipeline)

```
START
  │
  ▼
┌──────────────────────────────┐
│ Step 1: WiFi Connection      │  Connect to 2.4 GHz hotspot
│   Network authentication     │  WPA2-PSK
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 2: Fetch SUIT Manifest  │  HTTP GET /fw/manifest
│   Download binary manifest   │  Validate HTTP 200 + size
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 3: Validate Manifest    │  Check magic bytes = "SUIT"
│   Parse fields & bounds      │  Verify firmware size bounds
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 4: Anti-Rollback Check  │  manifest.seq > CURRENT_FW_VERSION
│   Reject older versions      │  Prevents downgrade attacks
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 5: Verify Signature     │  ed25519 (COSE_Sign1) verification
│   Trust anchor validation    │  Reject unauthorized firmware
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 6: Download Firmware    │  HTTP GET /fw/image
│   Streamed with progress     │  Content-Length validation
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 7: SHA-256 Integrity    │  Compute hash of downloaded FW
│   Compare with manifest      │  Reject if MISMATCH
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 8: Apply OTA Update     │  Write firmware to flash
│   (Simulation / Real)        │  ESP8266 OTA partition
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Step 9: Summary & Reboot     │  Print results table
│   LED status indicator       │  Reboot into new firmware
└──────────────────────────────┘
  │
  ▼
END → Run 6 Edge-Case Security Tests
```

---

## 🧪 Edge-Case Security Tests

After the normal update completes, the device automatically runs **6 attack simulations**:

| # | Attack Scenario | What It Tests | Caught At |
|---|----------------|---------------|-----------|
| 1 | **Corrupt Hash** | Manifest contains wrong SHA-256 digest | Step 7: Hash Verify |
| 2 | **Rollback Attack** | Manifest has seq=0 (older version) | Step 4: Anti-Rollback |
| 3 | **Invalid Signature** | Manifest has zeroed ed25519 signature | Step 5: Signature |
| 4 | **Bad Magic Bytes** | Manifest uses 0xDEADBEEF instead of "SUIT" | Step 2: Parse |
| 5 | **Tampered Firmware** | Firmware binary has one byte flipped | Step 7: Hash Verify |
| 6 | **Unauthorized Device** | Wrong X-Device-ID header sent | Step 2: HTTP 403 |

All 6 tests must result in **CORRECTLY REJECTED** for a passing score.

---

## 🛠️ Tools & Software

### Hardware

| Component | Specification |
|-----------|--------------|
| **Microcontroller** | NodeMCU 1.0 (ESP-12E Module) — ESP8266 |
| **CPU** | Tensilica L106, 80 MHz |
| **Flash** | 4 MB SPI Flash |
| **WiFi** | 802.11 b/g/n, 2.4 GHz only |
| **USB-Serial Chip** | CH340G (requires driver) |

### Software Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Firmware IDE** | Arduino IDE 2.x | Compile & upload ESP8266 sketch |
| **Board Package** | `esp8266` by ESP8266 Community | ESP8266 Arduino core |
| **Crypto Library** | BearSSL (built into ESP8266 core) | SHA-256 hash computation |
| **Server Runtime** | Node.js v14+ | Firmware update server |
| **Server Framework** | None (built-in `http`, `crypto`) | Zero-dependency HTTP server |
| **Desktop Compiler** | g++ (C++17) | Desktop prototype simulation |
| **Protocol** | HTTP/1.1 over WiFi | Firmware delivery (replaces CoAP) |
| **Manifest Standard** | SUIT (simplified binary format) | Firmware metadata envelope |
| **Signature** | ed25519 (COSE_Sign1 stub) | Firmware authenticity |
| **Hash** | SHA-256 | Firmware integrity |

### SUIT Manifest Binary Format

```
Offset  Size   Field
──────  ────   ────────────────────────────
0       4B     Magic: 0x53554954 ("SUIT")
4       4B     Sequence number (big-endian)
8       4B     Firmware size (big-endian)
12      1B     Format type (0x01 = raw binary)
13      1B     URI length (N)
14      NB     Firmware download URI string
14+N    32B    SHA-256 digest of firmware
46+N    64B    ed25519 signature
```

---

## 📂 Project Structure

```
btp/
├── node_server/                         ← Node.js Firmware Update Server
│   ├── server.js                        ← HTTP server (normal + 6 edge-case endpoints)
│   └── package.json
│
├── esp32_sketches/
│   └── nodemcu_ota_client/              ← ESP8266 OTA Client Sketch
│       └── nodemcu_ota_client.ino       ← Full update flow + edge tests + Snake & Ladders
│
├── prototype/                           ← Desktop C++ Simulation
│   ├── main.cpp                         ← Entry point (6-phase lifecycle)
│   ├── configs/build_configs.h          ← Flash layout, slot sizes, offsets
│   ├── bootloader/bootloader.cpp        ← Dual-slot boot selection logic
│   ├── crypto/verify.h + verify.cpp     ← SHA-256, ed25519 verification
│   ├── manifest/suit_parser.h + .cpp    ← SUIT manifest binary parser
│   ├── network/coap_client.h + .cpp     ← CoAP client (simulated)
│   ├── firmware/update_module.h + .cpp  ← Update orchestration module
│   ├── lwm2m/lwm2m_handler.cpp          ← LwM2M device management
│   ├── server/update_server.py          ← Python update server (alternative)
│   └── arduino_mock/firmware_update.ino ← Arduino mock sketch
│
├── README.md                            ← This file
├── walkthrough.md                       ← Step-by-step demo walkthrough
├── viva_preparation.md                  ← Viva Q&A preparation
├── paper_text.txt                       ← Reference paper text
└── Secure_Firmware_Updates_for_Constrained_IoT_Device.pdf
```

---

## 🚀 Quick Start

### 1. Start the Node.js Server

```bash
cd btp/node_server
node server.js
```

Note the printed IP address (e.g., `10.141.107.224`).

### 2. Configure & Upload ESP8266 Sketch

Edit 3 lines in `nodemcu_ota_client.ino`:

```cpp
const char* WIFI_SSID     = "YourHotspot";
const char* WIFI_PASSWORD = "YourPassword";
const char* SERVER_IP     = "10.141.107.224";  // from step 1
```

Upload via Arduino IDE → Open Serial Monitor at **115200 baud**.

### 3. Run Desktop Prototype (Optional)

```bash
cd btp/prototype
g++ -std=c++17 -o fw_update_demo main.cpp bootloader/bootloader.cpp firmware/update_module.cpp crypto/verify.cpp manifest/suit_parser.cpp network/coap_client.cpp
./fw_update_demo
```

---

## 🔐 Security Features Summary

| Feature | Implementation | Standard |
|---------|---------------|----------|
| **Integrity** | SHA-256 (BearSSL on ESP8266) | NIST FIPS 180-4 |
| **Authenticity** | ed25519 signature verification | RFC 8032 / COSE_Sign1 |
| **Anti-Rollback** | Monotonic sequence number comparison | SUIT §4.3 |
| **Manifest Validation** | Magic bytes + field bounds checking | SUIT (simplified) |
| **Device Authorization** | X-Device-ID HTTP header check | Custom (server-side) |
| **Tamper Detection** | Hash mismatch = firmware rejected | SHA-256 digest compare |

---

## 📄 License

Academic project — Secure IoT Firmware Update Framework.
