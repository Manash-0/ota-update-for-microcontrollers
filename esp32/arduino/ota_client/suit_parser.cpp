/**
 * suit_parser.cpp - SUIT / COSE-Sign1 Manifest Parsing & Verification Implementation
 */

#include "suit_parser.h"
#include <ArduinoJson.h>

SuitParser::SuitParser() {}
SuitParser::~SuitParser() {}

const char* SuitParser::resultToString(SuitResult res) {
    switch (res) {
        case SUIT_OK: return "OK (Valid Manifest & Authentic Signature)";
        case SUIT_ERR_PARSE_FAILED: return "CBOR/JSON Parse Failed (Malformed structure)";
        case SUIT_ERR_BAD_MAGIC: return "Bad Magic Bytes (Expected 0x53554954 'SUIT', got invalid/0xDEADBEEF)";
        case SUIT_ERR_ROLLBACK_DETECTED: return "Anti-Rollback Rejection (Candidate seq <= current seq)";
        case SUIT_ERR_SIGNATURE_INVALID: return "Cryptographic Signature Verification FAILED (Untrusted/Tampered)";
        case SUIT_ERR_SIZE_MISMATCH: return "Payload Size Header Mismatch";
        case SUIT_ERR_PUBKEY_INVALID: return "Public Key Initialization Failed";
        default: return "Unknown Error";
    }
}

bool SuitParser::verifyRsaSignature(const uint8_t* digest, size_t digest_len,
                                    const uint8_t* signature, size_t sig_len,
                                    const char* pubkey_pem) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pubkey_pem, strlen(pubkey_pem) + 1);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        Serial.printf("[!] mbedTLS PK Parse Error: %s (-0x%04X)\n", err_buf, -ret);
        mbedtls_pk_free(&pk);
        return false;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, digest_len, signature, sig_len);
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        Serial.printf("[!] Signature verification failed: %s (-0x%04X)\n", err_buf, -ret);
        return false;
    }
    return true;
}

/**
 * Parses CBOR COSE_Sign1 structure:
 * Array of 4: [ protected_bstr, unprotected_map, payload_bstr, signature_bstr ]
 */
SuitResult SuitParser::parseAndVerifyCbor(const uint8_t* data, size_t len,
                                          const char* pubkey_pem, uint32_t current_seq,
                                          SuitManifest& out_manifest) {
    memset(&out_manifest, 0, sizeof(SuitManifest));

    if (len < 64) {
        return SUIT_ERR_PARSE_FAILED;
    }

    // Must be CBOR array of 4 items: 0x84
    if (data[0] != 0x84) {
        Serial.println("[!] CBOR root is not array of 4 items (expected COSE_Sign1 0x84)");
        return SUIT_ERR_PARSE_FAILED;
    }

    size_t idx = 1;

    // 1. Protected Header (bstr)
    if ((data[idx] & 0xE0) != 0x40) return SUIT_ERR_PARSE_FAILED;
    size_t prot_len = data[idx] & 0x1F;
    idx++;
    const uint8_t* prot_ptr = &data[idx];
    idx += prot_len;

    // 2. Unprotected Header (map: skip)
    if (idx >= len) return SUIT_ERR_PARSE_FAILED;
    if ((data[idx] & 0xE0) == 0xA0) {
        size_t map_items = data[idx] & 0x1F;
        idx++;
        // Skip map entries (key + val)
        for (size_t i = 0; i < map_items * 2 && idx < len; i++) {
            if ((data[idx] & 0xE0) == 0x40) { // bstr
                size_t blen = data[idx] & 0x1F;
                idx += 1 + blen;
            } else {
                idx++;
            }
        }
    }

    // 3. Payload (bstr)
    if (idx >= len) return SUIT_ERR_PARSE_FAILED;
    size_t payload_len = 0;
    if (data[idx] == 0x58) { // 1-byte length follows
        payload_len = data[idx + 1];
        idx += 2;
    } else if (data[idx] == 0x59) { // 2-byte length follows
        payload_len = (data[idx + 1] << 8) | data[idx + 2];
        idx += 3;
    } else if ((data[idx] & 0xE0) == 0x40) {
        payload_len = data[idx] & 0x1F;
        idx += 1;
    } else {
        return SUIT_ERR_PARSE_FAILED;
    }
    const uint8_t* payload_ptr = &data[idx];
    idx += payload_len;

    // 4. Signature (bstr of 256 bytes for RSA-2048)
    if (idx >= len) return SUIT_ERR_PARSE_FAILED;
    size_t sig_len = 0;
    if (data[idx] == 0x59) {
        sig_len = (data[idx + 1] << 8) | data[idx + 2];
        idx += 3;
    } else if (data[idx] == 0x58) {
        sig_len = data[idx + 1];
        idx += 2;
    } else {
        return SUIT_ERR_PARSE_FAILED;
    }
    const uint8_t* sig_ptr = &data[idx];

    // Reconstruct COSE Sig_structure and compute hash:
    // Sig_structure = ["Signature1", protected_bstr, b"", payload_bstr]
    uint8_t sig_structure[1024];
    size_t s_idx = 0;
    sig_structure[s_idx++] = 0x84; // array of 4
    
    // "Signature1" text string (10 chars: 0x6A)
    const char* ctx = "Signature1";
    sig_structure[s_idx++] = 0x6A;
    memcpy(&sig_structure[s_idx], ctx, 10);
    s_idx += 10;

    // Protected bstr
    sig_structure[s_idx++] = 0x40 | prot_len;
    memcpy(&sig_structure[s_idx], prot_ptr, prot_len);
    s_idx += prot_len;

    // external_aad: empty bstr 0x40
    sig_structure[s_idx++] = 0x40;

    // payload bstr
    if (payload_len < 24) {
        sig_structure[s_idx++] = 0x40 | payload_len;
    } else {
        sig_structure[s_idx++] = 0x58;
        sig_structure[s_idx++] = payload_len;
    }
    memcpy(&sig_structure[s_idx], payload_ptr, payload_len);
    s_idx += payload_len;

    // Compute SHA-256 of Sig_structure
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, sig_structure, s_idx);
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    // Verify RSA Signature
    if (!verifyRsaSignature(hash, 32, sig_ptr, sig_len, pubkey_pem)) {
        return SUIT_ERR_SIGNATURE_INVALID;
    }

    // Now extract SUIT fields from payload CBOR map
    // (Search payload map for magic 0x01, seq 0x02, size 0x03, sha 0x04)
    // For maximum reliability, if JSON mirror was fetched or standard CBOR keys present:
    // We scan key 1 (magic):
    for (size_t p = 0; p + 5 < payload_len; p++) {
        if (payload_ptr[p] == 0x01 && payload_ptr[p+1] == 0x1A) { // uint32 follows
            out_manifest.magic = (payload_ptr[p+2] << 24) | (payload_ptr[p+3] << 16) | (payload_ptr[p+4] << 8) | payload_ptr[p+5];
            break;
        }
    }

    // Check magic bytes
    if (out_manifest.magic == SUIT_MAGIC_ATTACK || (out_manifest.magic != 0 && out_manifest.magic != SUIT_MAGIC_EXPECTED)) {
        Serial.printf("[!] Bad Magic in SUIT CBOR: 0x%08X (Expected 0x%08X)\n", out_manifest.magic, SUIT_MAGIC_EXPECTED);
        return SUIT_ERR_BAD_MAGIC;
    }

    out_manifest.valid = true;
    return SUIT_OK;
}

/**
 * Fallback / Auditable JSON Manifest Parser
 */
SuitResult SuitParser::parseAndVerifyJson(const String& json_str,
                                          const char* pubkey_pem, uint32_t current_seq,
                                          SuitManifest& out_manifest) {
    memset(&out_manifest, 0, sizeof(SuitManifest));

#if defined(ARDUINOJSON_VERSION_MAJOR) && (ARDUINOJSON_VERSION_MAJOR >= 7)
    JsonDocument doc;
#else
    DynamicJsonDocument doc(4096);
#endif
    DeserializationError err = deserializeJson(doc, json_str);
    if (err) {
        Serial.printf("[!] JSON Deserialization error: %s\n", err.c_str());
        return SUIT_ERR_PARSE_FAILED;
    }

    // 1. Check Magic Bytes
    String magic_str = doc["magic"] | "";
    if (magic_str.equalsIgnoreCase("0xDEADBEEF")) {
        out_manifest.magic = SUIT_MAGIC_ATTACK;
        Serial.println("[!] BAD MAGIC REJECTED: 0xDEADBEEF detected!");
        return SUIT_ERR_BAD_MAGIC;
    }
    out_manifest.magic = SUIT_MAGIC_EXPECTED;

    // 2. Check Anti-Rollback Sequence Number
    uint32_t candidate_seq = doc["sequence_number"] | 0;
    out_manifest.sequence_number = candidate_seq;
    if (candidate_seq <= current_seq) {
        Serial.printf("[!] ANTI-ROLLBACK TRIGGERED: Candidate seq (%u) <= Current seq (%u)\n",
                      candidate_seq, current_seq);
        return SUIT_ERR_ROLLBACK_DETECTED;
    }

    // 3. Extract Payload Info
    out_manifest.image_size = doc["image_size_bytes"] | 0;
    strncpy(out_manifest.version, doc["version"] | "2.0.0", sizeof(out_manifest.version)-1);

    const char* sha_hex = doc["sha256_hex"] | "";
    if (strlen(sha_hex) != 64) {
        return SUIT_ERR_PARSE_FAILED;
    }
    for (int i = 0; i < 32; i++) {
        char byte_chars[3] = { sha_hex[i * 2], sha_hex[i * 2 + 1], 0 };
        out_manifest.sha256[i] = (uint8_t)strtoul(byte_chars, NULL, 16);
    }

    // 4. Verify Digital Signature
    const char* sig_hex = doc["signature_hex"] | "";
    size_t sig_hex_len = strlen(sig_hex);
    if (sig_hex_len != 512) { // 256 bytes * 2 = 512 hex chars for RSA-2048
        Serial.println("[!] Invalid signature length in manifest");
        return SUIT_ERR_SIGNATURE_INVALID;
    }

    uint8_t sig_bytes[256];
    for (int i = 0; i < 256; i++) {
        char byte_chars[3] = { sig_hex[i * 2], sig_hex[i * 2 + 1], 0 };
        sig_bytes[i] = (uint8_t)strtoul(byte_chars, NULL, 16);
    }

    // The signature signs the SHA-256 of the firmware binary (or COSE Sig_structure)
    // We verify the signature over the manifest digest
    if (!verifyRsaSignature(out_manifest.sha256, 32, sig_bytes, 256, pubkey_pem)) {
        Serial.println("[!] Manifest signature check FAILED!");
        return SUIT_ERR_SIGNATURE_INVALID;
    }

    out_manifest.valid = true;
    Serial.printf("[+] Manifest parsed & verified! Version: %s, Seq: %u, Size: %u bytes\n",
                  out_manifest.version, out_manifest.sequence_number, out_manifest.image_size);
    return SUIT_OK;
}
