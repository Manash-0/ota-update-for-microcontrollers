/**
 * suit_parser.c - Pure C SUIT Parser & Cryptographic Validator
 */

#include "suit_parser.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"

static const char *TAG = "SUIT_PARSER";

const char* suit_result_to_str(suit_result_t res) {
    switch (res) {
        case SUIT_RES_OK:                return "OK - Valid & Authentic Manifest";
        case SUIT_RES_ERR_MAGIC:         return "REJECTED - Bad Magic Bytes (0xDEADBEEF)";
        case SUIT_RES_ERR_ROLLBACK:      return "REJECTED - Anti-Rollback Triggered (Candidate seq <= Current seq)";
        case SUIT_RES_ERR_SIG_INVALID:   return "REJECTED - Digital Signature Invalid / Tampered";
        case SUIT_RES_ERR_HASH_MISMATCH: return "REJECTED - Payload Hash Mismatch";
        default:                         return "REJECTED - Parse Error";
    }
}

suit_result_t suit_validate_manifest(const suit_manifest_t *manifest, uint32_t current_seq) {
    if (!manifest) {
        return SUIT_RES_ERR_PARSE;
    }

    // 1. Check Magic Bytes
    if (manifest->magic == SUIT_MAGIC_CORRUPT) {
        ESP_LOGE(TAG, "[!] Bad Magic Bytes detected: 0x%08lX (Expected 0x%08X)",
                 (unsigned long)manifest->magic, SUIT_MAGIC_VALID);
        return SUIT_RES_ERR_MAGIC;
    }

    if (manifest->magic != SUIT_MAGIC_VALID) {
        ESP_LOGE(TAG, "[!] Unknown header magic: 0x%08lX", (unsigned long)manifest->magic);
        return SUIT_RES_ERR_MAGIC;
    }

    // 2. Anti-Rollback Sequence Check
    if (manifest->sequence_number <= current_seq) {
        ESP_LOGW(TAG, "[!] Anti-Rollback Triggered! Candidate seq (%lu) <= Current seq (%lu)",
                 (unsigned long)manifest->sequence_number, (unsigned long)current_seq);
        return SUIT_RES_ERR_ROLLBACK;
    }

    return SUIT_RES_OK;
}

bool suit_verify_signature(const uint8_t *digest, size_t digest_len,
                           const uint8_t *signature, size_t sig_len,
                           const char *pubkey_pem) {
    if (!digest || !signature || !pubkey_pem) {
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pubkey_pem, strlen(pubkey_pem) + 1);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "mbedTLS public key parse error: %s (-0x%04X)", err_buf, -ret);
        mbedtls_pk_free(&pk);
        return false;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, digest_len, signature, sig_len);
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "mbedTLS signature verification failed: %s (-0x%04X)", err_buf, -ret);
        return false;
    }

    return true;
}
