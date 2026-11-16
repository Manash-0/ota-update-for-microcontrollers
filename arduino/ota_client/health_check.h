/**
 * health_check.h - ESP32-C6 OTA Two-Phase Commit & Health Verification
 */

#pragma once
#include <Arduino.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>

class HealthCheck {
public:
    static void checkAndValidate(bool simulate_buggy_v2);
    static void printPartitionDiagnostics();
};

