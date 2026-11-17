/**
 * attack_matrix.h - Pure C Security Attack Matrix Simulation Suite
 * Runs all 5 attack scenarios directly on the ESP32-C6 RISC-V microcontroller.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

void attack_matrix_run_all(void);

void attack_matrix_scenario_1_valid_signature(void);
void attack_matrix_scenario_2_tampered_payload(void);
void attack_matrix_scenario_3_anti_rollback(void);
void attack_matrix_scenario_4_flash_encryption_entropy(void);
void attack_matrix_scenario_5_two_phase_commit(void);

float calculate_shannon_entropy(const uint8_t *data, size_t len);
