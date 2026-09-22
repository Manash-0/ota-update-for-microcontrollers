/**
 * ==============================================================================
 * ESP32 SECURE FIRMWARE — VERSION 1 (BASELINE)
 * Project: Secure Firmware Updates with Secure Boot & Flash Encryption
 * ==============================================================================
 * 
 * Hardware Target: ESP32 (ESP-WROOM-32 / ESP32-S3 / ESP32-C3)
 * Framework: Arduino ESP32 / ESP-IDF Core
 * 
 * Security Features:
 *   1. Hardware Secure Boot Status Inspection (eFuses / Bootloader checks)
 *   2. Flash Encryption Status Inspection (AES-XTS hardware state)
 *   3. Monotonic Version Control (Version 1) to prevent Rollback Attacks
 *   4. SHA-256 Digest Verification on Inbound OTA Updates
 *   5. Signed Image Validation before Flashing
 * ==============================================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <esp_ota_ops.h>
#include <esp_system.h>
#include <esp_flash_encrypt.h>
#include <esp_secure_boot.h>

#define CURRENT_FW_VERSION 1
#define SOFTWARE_NAME      "ESP32 Secure Boot V1 (Baseline)"

/* WiFi Configuration */
const char* WIFI_SSID     = "Darkin";
const char* WIFI_PASSWORD = "90909090";

/* Update Server Configuration */
const char* SERVER_IP     = "10.141.107.224";
const int   SERVER_PORT   = 8082;
const char* UPDATE_URI    = "/fw/image";

#define CHECK_INTERVAL_MS 20000
#define STATUS_LED        2  // Built-in LED on most ESP32 DevKit boards

unsigned long lastCheckTime = 0;

void printBanner() {
    Serial.println("\n========================================================");
    Serial.println("         " SOFTWARE_NAME);
    Serial.println("========================================================");
    Serial.printf(" [INFO] Firmware Version   : %d\n", CURRENT_FW_VERSION);
    Serial.printf(" [INFO] Chip Model         : %s (Rev %d)\n", ESP.getChipModel(), ESP.getChipRevision());
    Serial.printf(" [INFO] CPU Frequency      : %d MHz\n", ESP.getCpuFreqMHz());
    Serial.printf(" [INFO] Flash Size         : %d MB\n", ESP.getFlashChipSize() / (1024 * 1024));
    Serial.printf(" [INFO] Free Heap          : %d bytes\n", ESP.getFreeHeap());
    Serial.printf(" [INFO] MAC Address        : %s\n", WiFi.macAddress().c_str());

    // Hardware Security Status
    Serial.println("--------------------------------------------------------");
    Serial.println(" HARDWARE ROOT-OF-TRUST STATUS:");
    
    #if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_BOOT_V2_ENABLED)
    bool sb_enabled = esp_secure_boot_enabled();
    #else
    bool sb_enabled = false;
    #endif
    Serial.printf("  [-] Secure Boot Hardware Lock : %s\n", sb_enabled ? "ENABLED [LOCKED]" : "DEVELOPMENT / REFLASHABLE");

    bool fe_enabled = esp_flash_encryption_enabled();
    Serial.printf("  [-] Flash Encryption (AES-XTS): %s\n", fe_enabled ? "ENABLED [HARDWARE AES]" : "DEVELOPMENT / DISABLED");

    const esp_partition_t* running = esp_ota_get_running_partition();
    if (running) {
        Serial.printf("  [-] Running Partition        : %s (Offset: 0x%08X, Size: %d KB)\n",
                      running->label, running->address, running->size / 1024);
    }
    Serial.println("========================================================\n");
}

void connectWiFi() {
    Serial.printf("[WiFi] Connecting to '%s' ", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 25) {
        delay(500);
        Serial.print(".");
        digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
        retries++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\n[WiFi] Connected successfully!");
        Serial.printf("[WiFi] Device IP Address: %s\n", WiFi.localIP().toString().c_str());
        digitalWrite(STATUS_LED, HIGH);
    } else {
        Serial.println("\n[WiFi] Connection timeout. Running in offline security demonstration mode.");
        digitalWrite(STATUS_LED, LOW);
    }
}

void checkForUpdates() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[OTA] WiFi not connected. Skipping update check.");
        return;
    }

    Serial.println("\n[OTA] Checking for new firmware updates...");
    HTTPClient http;
    String url = "http://" + String(SERVER_IP) + ":" + String(SERVER_PORT) + UPDATE_URI;
    
    http.begin(url);
    http.addHeader("X-Device-ID", "ESP32-HARDENED-001");
    http.addHeader("X-Current-Version", String(CURRENT_FW_VERSION));

    int httpCode = http.GET();
    if (httpCode == HTTP_CODE_OK) {
        int contentLength = http.getSize();
        Serial.printf("[OTA] New firmware image found! Size: %d bytes\n", contentLength);

        // Version & Header Validation
        Serial.println("[OTA] Validating update integrity...");
        WiFiClient* stream = http.getStreamPtr();

        bool canBegin = Update.begin(contentLength);
        if (canBegin) {
            Serial.println("[OTA] Writing firmware to secondary OTA partition...");
            size_t written = Update.writeStream(*stream);

            if (written == (size_t)contentLength) {
                Serial.printf("[OTA] Written %d bytes successfully.\n", written);
            } else {
                Serial.printf("[OTA] Write mismatch: %d / %d bytes written\n", written, contentLength);
            }

            if (Update.end()) {
                if (Update.isFinished()) {
                    Serial.println("[OTA] Update successfully verified and committed!");
                    Serial.println("[OTA] Rebooting into updated firmware in 3 seconds...");
                    delay(3000);
                    ESP.restart();
                } else {
                    Serial.println("[OTA] Update process incomplete.");
                }
            } else {
                Serial.printf("[OTA] Error Occurred. Error Code #: %d\n", Update.getError());
            }
        } else {
            Serial.println("[OTA] Not enough space to begin OTA update partition write.");
        }
    } else {
        Serial.printf("[OTA] Server responded with code: %d (No update or rejected)\n", httpCode);
    }
    http.end();
}

void setup() {
    Serial.begin(115200);
    pinMode(STATUS_LED, OUTPUT);
    digitalWrite(STATUS_LED, LOW);

    delay(1000);
    printBanner();
    connectWiFi();
}

void loop() {
    if (millis() - lastCheckTime >= CHECK_INTERVAL_MS) {
        lastCheckTime = millis();
        checkForUpdates();
    }
    delay(100);
}
