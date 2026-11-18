/**
 * attack_matrix.h - Pure C Security Attack Matrix Simulation Suite
 * Runs 10 comprehensive security attack scenarios directly on the ESP32-C6 RISC-V microcontroller.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

void attack_matrix_run_all(void);

// Core Hardware Security Scenarios
void attack_matrix_scenario_1_valid_signature(void);
void attack_matrix_scenario_2_tampered_payload(void);
void attack_matrix_scenario_3_anti_rollback(void);
void attack_matrix_scenario_4_flash_encryption_entropy(void);
void attack_matrix_scenario_5_two_phase_commit(void);

// Extended Attacks: Health Check, RSA-PSS, HTTPS/TLS & Header Validation
void attack_matrix_scenario_6_health_check_heap_starvation(void);
void attack_matrix_scenario_7_health_check_watchdog_timeout(void);
void attack_matrix_scenario_8_rsa_pss_tampered_salt(void);
void attack_matrix_scenario_9_https_untrusted_ca_mitm(void);
void attack_matrix_scenario_10_bad_magic_bytes(void);

float calculate_shannon_entropy(const uint8_t *data, size_t len);
