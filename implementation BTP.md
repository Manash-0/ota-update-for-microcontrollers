#### **OLD Review:**



&#x20;                   ESP8266

&#x20;                      │

&#x20;       ┌──────────────┼──────────────┐

&#x20;       │              │              │

&#x20;       ▼              ▼              ▼

&#x20;     TASK 1         TASK 2         TASK 3

&#x20;       │              │              │

&#x20;  No Security      Checksum       SHA-256

&#x20;       │              │              │

&#x20;  No Integrity     Integrity      Authentication

&#x20;       │              │              │

&#x20;  No Auth          No Auth        Anti-Rollback

&#x20;       │              │              │

&#x20;  Manual Update    Manual Update   Automatic Update

&#x20;       │              │              │

&#x20;  Bricking         Bricking       No Bricking





✓ Task 1

&#x20; No authentication

&#x20; No integrity

&#x20; No rollback

&#x20; Manual update

&#x20; Bricking demonstration



&#x20;       ↓



✓ Task 2

&#x20; Checksum

&#x20; No authentication

&#x20; No rollback

&#x20; Manual update

&#x20; Bricking demonstration



&#x20;       ↓



✓ Task 3

&#x20; SHA-256

&#x20; Authentication

&#x20; Anti-rollback

&#x20; Automatic update

&#x20; Python HTTP server

&#x20; No bricking







##### **New Extented version:**







                       ESP32

&#x20;                        │

&#x20;                        ▼

&#x20;               Basic Firmware

&#x20;                        │

&#x20;                        ▼

&#x20;                Firmware Signing

&#x20;                        │

&#x20;                        ▼

&#x20;                 SECURE BOOT

&#x20;                        │

&#x20;             ┌──────────┴──────────┐

&#x20;             │                     │

&#x20;             ▼                     ▼

&#x20;      Signed Bootloader      Signed Application

&#x20;             │                     │

&#x20;             └──────────┬──────────┘

&#x20;                        ▼

&#x20;                FLASH ENCRYPTION

&#x20;                        │

&#x20;                        ▼

&#x20;                 Encrypted Flash

&#x20;                        │

&#x20;                        ▼

&#x20;                Secure Execution





1. Identify exact ESP32

&#x20;       ↓

2\. Install ESP-IDF

&#x20;       ↓

3\. Basic ESP32 firmware

&#x20;       ↓

4\. Port V1/V2

&#x20;       ↓

5\. Firmware signing

&#x20;       ↓

6\. Secure Boot development setup

&#x20;       ↓

7\. Signed V1 → successful boot

&#x20;       ↓

8\. Modified/unsigned V2 → rejection

&#x20;       ↓

9\. Verify Secure Boot behavior

&#x20;       ↓

10\. Flash Encryption development setup

&#x20;       ↓

11\. Verify encrypted flash

&#x20;       ↓

12\. Combine Secure Boot + Flash Encryption

&#x20;       ↓

13\. Run final attack matrix

&#x20;       ↓

14\. Document results




