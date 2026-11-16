/**
 * suit_parser.h - SUIT / COSE-Sign1 Manifest Parsing & Verification
 * Implements RFC 9124 / RFC 8152 verification on ESP32-C6 using mbedTLS.
 */

#pragma once
#include <Arduino.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>

#define SUIT_MAGIC_EXPECTED 0x53554954  // "SUIT" in hex
#define SUIT_MAGIC_ATTACK   0xDEADBEEF

struct SuitManifest {
    uint32_t magic;
    uint32_t sequence_number;
    uint32_t image_size;
    uint8_t  sha256[32];
    char     version[16];
    char     vendor_id[32];
    char     device_class[32];
    bool     valid;
};

// Error codes for manifest validation
enum SuitResult {
    SUIT_OK = 0,
    SUIT_ERR_PARSE_FAILED,
    SUIT_ERR_BAD_MAGIC,
    SUIT_ERR_ROLLBACK_DETECTED,
    SUIT_ERR_SIGNATURE_INVALID,
    SUIT_ERR_SIZE_MISMATCH,
    SUIT_ERR_PUBKEY_INVALID
};

class SuitParser {
public:
    SuitParser();
    ~SuitParser();

    /**
     * Parse binary CBOR / COSE-Sign1 manifest envelope (RFC 9124)
     * and verify RSA-2048 digital signature.
     */
    SuitResult parseAndVerifyCbor(const uint8_t* cbor_data, size_t cbor_len,
                                 const char* pubkey_pem, uint32_t current_seq,
                                 SuitManifest& out_manifest);

    /**
     * Fallback parser for human-readable JSON manifest
     */
    SuitResult parseAndVerifyJson(const String& json_str,
                                 const char* pubkey_pem, uint32_t current_seq,
                                 SuitManifest& out_manifest);

    static const char* resultToString(SuitResult res);

private:
    bool verifyRsaSignature(const uint8_t* digest, size_t digest_len,
                            const uint8_t* signature, size_t sig_len,
                            const char* pubkey_pem);
};

