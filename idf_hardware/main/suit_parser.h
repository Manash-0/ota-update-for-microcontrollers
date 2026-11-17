/**
 * suit_parser.h - Pure C SUIT Manifest & COSE-Sign1 Parser for ESP-IDF
 * Target: ESP32-C6 RISC-V Architecture
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SUIT_MAGIC_VALID    0x53554954  // "SUIT" in ASCII hex
#define SUIT_MAGIC_CORRUPT  0xDEADBEEF

typedef struct {
    uint32_t magic;
    uint32_t sequence_number;
    uint32_t image_size;
    uint8_t  sha256[32];
    char     version[16];
    char     device_class[32];
    bool     is_valid;
} suit_manifest_t;

typedef enum {
    SUIT_RES_OK = 0,
    SUIT_RES_ERR_MAGIC,
    SUIT_RES_ERR_ROLLBACK,
    SUIT_RES_ERR_SIG_INVALID,
    SUIT_RES_ERR_HASH_MISMATCH,
    SUIT_RES_ERR_PARSE
} suit_result_t;

/**
 * Validate a SUIT manifest in pure C
 */
suit_result_t suit_validate_manifest(const suit_manifest_t *manifest, uint32_t current_seq);

/**
 * Verify RSA-2048/3072 signature over SHA-256 digest using mbedTLS in C
 */
bool suit_verify_signature(const uint8_t *digest, size_t digest_len,
                           const uint8_t *signature, size_t sig_len,
                           const char *pubkey_pem);

const char* suit_result_to_str(suit_result_t res);
