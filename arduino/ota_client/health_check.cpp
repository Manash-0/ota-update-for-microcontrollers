/**
 * health_check.cpp - Two-Phase Commit & Rollback Implementation
 */

#include "health_check.h"

void HealthCheck::printPartitionDiagnostics() {
    const esp_partition_t* running = esp_ota_get_running_partition();
    const esp_partition_t* configured = esp_ota_get_boot_partition();

    Serial.println("\n----------------- Partition Diagnostics -----------------");
    if (configured != NULL) {
        Serial.printf("[*] Configured Boot Partition: %s (Type 0x%02X, Sub 0x%02X, Offset 0x%08X)\n",
                      configured->label, configured->type, configured->subtype, configured->address);
    }
    if (running != NULL) {
        Serial.printf("[*] Currently Running Partition: %s (Offset 0x%08X, Size %u KB)\n",
                      running->label, running->address, running->size / 1024);
        
        esp_ota_img_states_t state;
        esp_err_t err = esp_ota_get_state_partition(running, &state);
        if (err == ESP_OK) {
            const char* state_str = "UNKNOWN";
            switch (state) {
                case ESP_OTA_IMG_NEW:             state_str = "NEW"; break;
                case ESP_OTA_IMG_PENDING_VERIFY:  state_str = "PENDING_VERIFY (Candidate Under Evaluation)"; break;
                case ESP_OTA_IMG_VALID:           state_str = "VALID (Confirmed Healthy)"; break;
                case ESP_OTA_IMG_INVALID:         state_str = "INVALID"; break;
                case ESP_OTA_IMG_ABORTED:         state_str = "ABORTED"; break;
                case ESP_OTA_IMG_UNDEFINED:       state_str = "UNDEFINED (Factory / Initial Flash)"; break;
            }
            Serial.printf("[*] Running Image State: %s (0x%02X)\n", state_str, state);
        } else {
            Serial.println("[*] Partition state: Factory/Default (No otadata record yet)");
        }
    }
    Serial.println("---------------------------------------------------------\n");
}

void HealthCheck::checkAndValidate(bool simulate_buggy_v2) {
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) return;

    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) != ESP_OK) {
        Serial.println("[*] Health Check: Initial factory partition. No rollback pending.");
        return;
    }

    if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
        Serial.println("\n========================================================");
        Serial.println("  [!] CANDIDATE FIRMWARE DETECTED: PENDING_VERIFY");
        Serial.println("  Running Pre-Commit System Health Diagnostics...");
        Serial.println("========================================================");

        // Simulation for Attack Matrix Test 5: Signed but Buggy V2
        if (simulate_buggy_v2) {
            Serial.println("\n[!] FATAL SIMULATED BUG DETECTED in V2!");
            Serial.println("[!] Health check FAILED: Service crashed or watchdog tripped.");
            Serial.println("[!] Triggering Hardware Two-Phase Commit ROLLBACK to V1...");
            delay(1500);
            
            // Revert bootloader otadata pointer back to previously valid partition and reboot
            esp_ota_mark_app_invalid_rollback_and_reboot();
            
            // Code here should never be reached
            while(true) { delay(100); }
        }

        // Genuine health check: Verify critical heap and peripherals
        uint32_t free_heap = ESP.getFreeHeap();
        Serial.printf("[+] Free Internal SRAM Heap: %u bytes\n", free_heap);

        if (free_heap < 20000) {
            Serial.println("[!] Insufficient heap available! Rolling back...");
            esp_ota_mark_app_invalid_rollback_and_reboot();
            while(true) { delay(100); }
        }

        // If all health checks pass, permanently confirm the partition
        Serial.println("[+] ALL HEALTH CHECKS PASSED!");
        Serial.println("[+] Executing Two-Phase Commit: Marking image as permanently VALID.");
        esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
        if (err == ESP_OK) {
            Serial.println("[+] Update permanently committed to otadata! Candidate is now golden.\n");
        } else {
            Serial.printf("[!] Failed to mark app valid: 0x%04X\n", err);
        }
    }
}

