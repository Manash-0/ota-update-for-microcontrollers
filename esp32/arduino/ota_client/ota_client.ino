/**
 * ota_client.ino - Secure Firmware Update Client for ESP32-C6
 * 
 * Hardware: Smartelex ESP32-C6 Pico Dev Board (USB-C)
 * Framework: Arduino ESP32 Core 3.x
 * Features:
 *   - Hardware Root of Trust TLS with Root CA Certificate Pinning
 *   - Optional Hardware/Software mTLS Device Authentication
 *   - RFC 9124 SUIT / RFC 8152 COSE-Sign1 Manifest Parsing & Verification
 *   - Hardware-Accelerated SHA-256 & RSA-2048 Digital Signature Check
 *   - Monotonic Anti-Rollback Sequence Counter Enforcement
 *   - A/B Dual Partitioning (ota_0 / ota_1) with Atomic Switching
 *   - Two-Phase Commit Health Check & Automatic Rollback on Failure
 *   - Telemetry Benchmarks (Handshake time, OTA speed, Boot diagnostics)
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/sha256.h>

#if __has_include("secrets.h")
#include "secrets.h"
#else
#include "secrets.h.example"
#endif

#include "ca_cert.h"

#if __has_include("client_cert.h")
#include "client_cert.h"
#else
#include "client_cert.h.example"
#endif

#include "firmware_pubkey.h"
#include "suit_parser.h"
#include "health_check.h"

// Global instances
SuitParser suitParser;
bool otaTriggered = false;

void printBanner() {
    Serial.println("\n========================================================");
    Serial.println("   ESP32-C6 SECURE OTA FIRMWARE FRAMEWORK (TRACK A)     ");
    Serial.println("========================================================");
    Serial.printf(" [*] Firmware Version:     %s\n", FIRMWARE_VERSION);
    Serial.printf(" [*] Sequence Number:      %u\n", SEQUENCE_NUMBER);
    Serial.printf(" [*] Device ID:            %s\n", DEVICE_ID);
    Serial.printf(" [*] mTLS Enabled:         %s\n", ENABLE_MTLS ? "TRUE (Strict Client Auth)" : "FALSE (Header Baseline)");
    Serial.printf(" [*] Buggy V2 Sim Mode:    %s\n", SIMULATE_BUGGY_V2 ? "TRUE (Trigger Rollback)" : "FALSE (Normal)");
    Serial.println("========================================================\n");
}

void connectWiFi() {
    Serial.printf("[*] Connecting to Wi-Fi SSID: '%s'", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long start_ms = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start_ms < 15000) {
        delay(500);
        Serial.print(".");
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[+] Wi-Fi Connected! IP: %s | RSSI: %d dBm | Time: %lu ms\n\n",
                      WiFi.localIP().toString().c_str(), WiFi.RSSI(), millis() - start_ms);
    } else {
        Serial.println("[!] Wi-Fi Connection FAILED! Check credentials in secrets.h.\n");
    }
}

void performSecureOTA() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[!] Cannot start OTA: Wi-Fi disconnected.");
        return;
    }

    Serial.println("\n>>>>>>>>>>>>>>> INITIATING SECURE OTA UPDATE SEQUENCE <<<<<<<<<<<<<<<");
    unsigned long total_start_time = millis();

    // 1. Configure Secure TLS Client
    WiFiClientSecure client;
    client.setCACert(ROOT_CA_CERT); // Pin trusted Certificate Authority

    if (ENABLE_MTLS) {
        Serial.println("[*] Provisioning mTLS Client Certificate & Private Key...");
        client.setCertificate(CLIENT_CERT);
        client.setPrivateKey(CLIENT_KEY);
    }

    // Measure TLS Handshake Benchmark
    Serial.printf("[*] Connecting to Secure OTA Server at https://%s:%d ...\n",
                  OTA_SERVER_HOST, OTA_SERVER_PORT);
    unsigned long hs_start = millis();
    if (!client.connect(OTA_SERVER_HOST, OTA_SERVER_PORT)) {
        Serial.println("[!] TLS Connection / Handshake FAILED! Check server status, IP, and certificates.");
        return;
    }
    unsigned long hs_duration = millis() - hs_start;
    Serial.printf("[+] [BENCHMARK] TLS Handshake Successful in %lu ms\n", hs_duration);
    client.stop(); // Clean disconnect for HTTPClient wrapper

    // 2. Fetch SUIT Manifest over HTTPS
    HTTPClient https;
    String manifest_url = String("https://") + OTA_SERVER_HOST + ":" + OTA_SERVER_PORT + "/ota/manifest.json";
    https.begin(client, manifest_url);
    https.addHeader("X-Device-ID", DEVICE_ID);

    Serial.printf("[*] Downloading SUIT Manifest from %s ...\n", manifest_url.c_str());
    int http_code = https.GET();

    if (http_code == 403) {
        Serial.println("[!] ATTACK MATRIX TEST 9 RESULT: Server returned HTTP 403 Forbidden!");
        Serial.println("[+] [SECURITY VERIFIED] Unauthorized device ID was correctly denied by server.");
        https.end();
        return;
    }

    if (http_code != 200) {
        Serial.printf("[!] Failed to fetch manifest! HTTP Code: %d\n", http_code);
        https.end();
        return;
    }

    String manifest_json = https.getString();
    https.end();
    Serial.printf("[+] Received Manifest (%u bytes)\n", manifest_json.length());

    // 3. Cryptographic Verification of Manifest
    Serial.println("\n--- Step 1: Manifest Verification ---");
    SuitManifest manifest;
    unsigned long verif_start = millis();
    SuitResult suit_res = suitParser.parseAndVerifyJson(manifest_json, FIRMWARE_SIGN_PUBKEY, SEQUENCE_NUMBER, manifest);
    unsigned long verif_duration = millis() - verif_start;

    if (suit_res != SUIT_OK) {
        Serial.printf("[!] OTA ABORTED: %s\n", SuitParser::resultToString(suit_res));
        if (suit_res == SUIT_ERR_BAD_MAGIC) {
            Serial.println("[+] [ATTACK MATRIX TEST 8] BAD MAGIC BYTES CORRECTLY REJECTED!");
        } else if (suit_res == SUIT_ERR_ROLLBACK_DETECTED) {
            Serial.println("[+] [ATTACK MATRIX TEST 4] OLDER FIRMWARE ROLLBACK CORRECTLY REJECTED!");
        } else if (suit_res == SUIT_ERR_SIGNATURE_INVALID) {
            Serial.println("[+] [ATTACK MATRIX TEST 2/3] UNTRUSTED / TAMPERED SIGNATURE CORRECTLY REJECTED!");
        }
        return;
    }
    Serial.printf("[+] [BENCHMARK] RSA-2048 Signature Verified in %lu ms\n", verif_duration);

    // 4. Download Firmware Binary & Stream into Flash
    Serial.println("\n--- Step 2: Firmware Download & Dual-Partition Write ---");
    String firmware_url = String("https://") + OTA_SERVER_HOST + ":" + OTA_SERVER_PORT + "/ota/firmware.bin";
    https.begin(client, firmware_url);
    https.addHeader("X-Device-ID", DEVICE_ID);

    http_code = https.GET();
    if (http_code != 200) {
        Serial.printf("[!] Failed to download firmware binary! HTTP Code: %d\n", http_code);
        https.end();
        return;
    }

    int content_len = https.getSize();
    Serial.printf("[*] Firmware Image Size: %d bytes (Manifest announced: %u bytes)\n",
                  content_len, manifest.image_size);

    if (content_len != manifest.image_size) {
        Serial.println("[!] Image size does not match manifest declaration! Aborting.");
        https.end();
        return;
    }

    // Allocate OTA Flash Partition
    if (!Update.begin(manifest.image_size, U_FLASH)) {
        Serial.printf("[!] Not enough flash partition space for OTA: %s\n", Update.errorString());
        https.end();
        return;
    }

    // Prepare streaming SHA-256 context
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);

    WiFiClient* stream = https.getStreamPtr();
    uint8_t buff[1024];
    size_t written = 0;
    unsigned long dl_start = millis();

    Serial.print("[*] Flashing candidate partition");
    while (https.connected() && (written < manifest.image_size)) {
        size_t available_bytes = stream->available();
        if (available_bytes > 0) {
            size_t to_read = available_bytes > sizeof(buff) ? sizeof(buff) : available_bytes;
            if (written + to_read > manifest.image_size) {
                to_read = manifest.image_size - written;
            }

            int bytes_read = stream->readBytes(buff, to_read);
            if (bytes_read > 0) {
                // Update running hash
                mbedtls_sha256_update(&sha256_ctx, buff, bytes_read);

                // Write to inactive OTA partition
                Update.write(buff, bytes_read);
                written += bytes_read;

                if (written % 16384 == 0) {
                    Serial.print(".");
                }
            }
        }
        delay(1);
    }
    Serial.println();
    https.end();

    unsigned long dl_duration = millis() - dl_start;
    float transfer_speed = (written / 1024.0) / (dl_duration / 1000.0);
    Serial.printf("[+] [BENCHMARK] Downloaded %u bytes in %lu ms (%.2f KB/s)\n",
                  written, dl_duration, transfer_speed);

    // 5. Finalize and Verify SHA-256 Digest
    Serial.println("\n--- Step 3: Payload Integrity Verification ---");
    uint8_t computed_sha256[32];
    mbedtls_sha256_finish(&sha256_ctx, computed_sha256);
    mbedtls_sha256_free(&sha256_ctx);

    bool hash_matched = (memcmp(computed_sha256, manifest.sha256, 32) == 0);
    if (!hash_matched) {
        Serial.println("[!] PAYLOAD HASH INTEGRITY MISMATCH!");
        Serial.println("[+] [ATTACK MATRIX TEST 7] CORRUPTED FIRMWARE / HASH CORRECTLY REJECTED!");
        Update.abort();
        return;
    }
    Serial.println("[+] SHA-256 Digest Matched Perfectly! Firmware is authentic & untampered.");

    // Commit flash update (Marks candidate slot as PENDING_VERIFY)
    if (!Update.end(true)) {
        Serial.printf("[!] Flash write finalization failed: %s\n", Update.errorString());
        return;
    }

    unsigned long total_duration = millis() - total_start_time;
    Serial.println("\n========================================================");
    Serial.println("  [+] OTA UPDATE WRITTEN SUCCESSFULLY!                  ");
    Serial.printf("  Total Elapsed Update Time: %lu ms\n", total_duration);
    Serial.println("  Candidate set to PENDING_VERIFY in otadata.           ");
    Serial.println("  Rebooting into Candidate Partition in 3 seconds...    ");
    Serial.println("========================================================\n");
    delay(3000);
    ESP.restart();
}

void setup() {
    Serial.begin(115200);

    // Wait 2.5 seconds for USB CDC Serial Monitor connection on ESP32-C6
    delay(2500);

    printBanner();

    // 1. Diagnostics & Health Check (Two-Phase Commit)
    HealthCheck::printPartitionDiagnostics();
    HealthCheck::checkAndValidate(SIMULATE_BUGGY_V2);

    // 2. Connect to Network
    connectWiFi();

    Serial.println("[*] Type 'u' or 'update' in Serial Monitor to trigger an OTA check,");
    Serial.println("[*] or wait 10 seconds for automatic update initiation...\n");
}

void loop() {
    // Check for serial user command
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd.equalsIgnoreCase("u") || cmd.equalsIgnoreCase("update")) {
            performSecureOTA();
        }
    }

    // Auto-trigger update once after 10 seconds on V1
    static unsigned long boot_timer = millis();
    if (!otaTriggered && (millis() - boot_timer > 10000) && (SEQUENCE_NUMBER == 1)) {
        otaTriggered = true;
        Serial.println("[*] Auto-initiating initial update sequence check...");
        performSecureOTA();
    }

    delay(100);
}

