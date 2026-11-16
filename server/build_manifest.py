#!/usr/bin/env python3
"""
build_manifest.py - Real SUIT (RFC 9124) / COSE-Sign1 Manifest Generator
Constructs a CBOR-encoded, COSE-signed SUIT manifest for firmware images.

Structure:
  COSE_Sign1 Envelope (RFC 8152 / RFC 9052):
    1. Protected Header:  {1: -257} (alg: RS256 - RSASSA-PKCS1-v1_5 with SHA-256)
    2. Unprotected Header: {4: kid}
    3. Payload (CBOR map representing SUIT manifest):
       - 0x01: Magic number 0x53554954 ("SUIT")
       - 0x02: Sequence Number (Monotonic anti-rollback counter)
       - 0x03: Firmware Image Size (bytes)
       - 0x04: SHA-256 Digest (32 raw bytes)
       - 0x05: Vendor ID string
       - 0x06: Class ID string ("ESP32-C6")
       - 0x07: Human-readable version string ("2.0.0")
    4. Signature: RSA-2048 signature over COSE Sig_structure:
       Sig_structure = ["Signature1", protected_bytes, b"", payload]

Also emits a companion manifest.json for transparency and debugging.
Supports attack simulation flags for the 9-test attack matrix.
"""

import sys
import os
import argparse
import hashlib
import json
from pathlib import Path

try:
    import cbor2
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[!] Required packages missing. Run: pip install -r requirements.txt")
    sys.exit(1)

MAGIC_SUIT = 0x53554954  # "SUIT" in ASCII hex


def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.digest()


def create_cose_sig_structure(protected_bstr, payload_bstr):
    """
    Constructs the canonical COSE Sig_structure for Signature1:
    Sig_structure = [
        "Signature1",      # context
        protected_bstr,    # body_protected
        b"",               # external_aad
        payload_bstr       # payload
    ]
    """
    sig_struct = ["Signature1", protected_bstr, b"", payload_bstr]
    return cbor2.dumps(sig_struct)


def sign_payload(sig_structure_bytes, private_key_path):
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    signature = priv_key.sign(
        sig_structure_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def build_manifest(bin_path, priv_key_path, output_dir, seq_num=2, version="2.0.0",
                   corrupt_hash=False, bad_magic=False, tamper_sig=False, old_seq=False):
    bin_path = Path(bin_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not bin_path.exists():
        print(f"[!] Firmware binary not found: {bin_path}")
        sys.exit(1)

    file_size = bin_path.stat().st_size
    actual_sha256 = compute_sha256(bin_path)

    # Apply attack transformations if requested
    magic = 0xDEADBEEF if bad_magic else MAGIC_SUIT
    sha256_digest = hashlib.sha256(b"corrupted_payload").digest() if corrupt_hash else actual_sha256
    sequence = 0 if old_seq else seq_num

    # 1. Construct SUIT payload map
    suit_payload = {
        1: magic,                       # Magic number
        2: sequence,                    # Anti-rollback sequence number
        3: file_size,                   # File size in bytes
        4: sha256_digest,               # SHA-256 digest (32 bytes)
        5: "BTP-Secure-IoT",            # Vendor ID
        6: "ESP32-C6",                  # Device Class
        7: version                      # Version string
    }
    payload_bstr = cbor2.dumps(suit_payload)

    # 2. Construct Protected Header: {1: -257} -> RS256 algorithm
    protected_header = {1: -257}
    protected_bstr = cbor2.dumps(protected_header)

    # 3. Form COSE Sig_structure and compute RSA signature
    sig_struct_bytes = create_cose_sig_structure(protected_bstr, payload_bstr)
    signature = sign_payload(sig_struct_bytes, priv_key_path)

    if tamper_sig:
        # Corrupt the signature by flipping the last byte
        sig_list = bytearray(signature)
        sig_list[-1] ^= 0xFF
        signature = bytes(sig_list)

    # 4. Construct complete COSE_Sign1 structure:
    # COSE_Sign1 = [ protected_bstr, unprotected_map, payload_bstr, signature ]
    unprotected_header = {4: b"key-btp-01"}  # key identifier (kid)
    cose_sign1 = [
        protected_bstr,
        unprotected_header,
        payload_bstr,
        signature
    ]
    cbor_manifest_bytes = cbor2.dumps(cose_sign1)

    # 5. Write binary CBOR manifest
    cbor_path = output_dir / "manifest.cbor"
    with open(cbor_path, "wb") as f:
        f.write(cbor_manifest_bytes)

    # 6. Write human-readable JSON manifest (for audit & simple parser fallback)
    json_manifest = {
        "standard": "RFC 9124 SUIT / RFC 8152 COSE-Sign1",
        "magic": f"0x{magic:08X}",
        "sequence_number": sequence,
        "image_size_bytes": file_size,
        "sha256_hex": sha256_digest.hex(),
        "vendor_id": "BTP-Secure-IoT",
        "device_class": "ESP32-C6",
        "version": version,
        "signature_hex": signature.hex(),
        "cbor_envelope_size": len(cbor_manifest_bytes),
        "flags": {
            "corrupt_hash": corrupt_hash,
            "bad_magic": bad_magic,
            "tampered_signature": tamper_sig,
            "old_sequence": old_seq
        }
    }
    json_path = output_dir / "manifest.json"
    with open(json_path, "w") as f:
        json.dump(json_manifest, f, indent=2)

    print(f"[+] Manifest built successfully:")
    print(f"    - CBOR/COSE: {cbor_path} ({len(cbor_manifest_bytes)} bytes)")
    print(f"    - JSON:      {json_path}")
    print(f"    - Sequence:  {sequence}")
    print(f"    - SHA-256:   {sha256_digest.hex()[:16]}...")
    if corrupt_hash or bad_magic or tamper_sig or old_seq:
        print(f"    [!] ATTACK MUTATIONS APPLIED:")
        if corrupt_hash: print("        * Hash corrupted")
        if bad_magic:    print("        * Bad magic 0xDEADBEEF")
        if tamper_sig:   print("        * Signature corrupted")
        if old_seq:      print("        * Rollback sequence forced")
    return cbor_path, json_path


def main():
    parser = argparse.ArgumentParser(description="Build SUIT CBOR/COSE Manifest for ESP32-C6 Firmware")
    parser.add_argument("--bin", required=True, help="Path to compiled firmware binary (.bin)")
    parser.add_argument("--key", default="keys/firmware_sign_priv.pem", help="Path to RSA private signing key")
    parser.add_argument("--out", default=".", help="Output directory for manifests")
    parser.add_argument("--seq", type=int, default=2, help="Monotonic sequence number (default 2)")
    parser.add_argument("--ver", default="2.0.0", help="Firmware version string")
    
    # Attack test switches
    parser.add_argument("--corrupt-hash", action="store_true", help="Attack Test 7: Corrupt SHA-256 hash")
    parser.add_argument("--bad-magic", action="store_true", help="Attack Test 8: Set magic to 0xDEADBEEF")
    parser.add_argument("--tamper-sig", action="store_true", help="Attack Test 2/3: Corrupt digital signature")
    parser.add_argument("--old-seq", action="store_true", help="Attack Test 4: Rollback attack (older sequence)")

    args = parser.parse_args()
    build_manifest(
        bin_path=args.bin,
        priv_key_path=args.key,
        output_dir=args.out,
        seq_num=args.seq,
        version=args.ver,
        corrupt_hash=args.corrupt_hash,
        bad_magic=args.bad_magic,
        tamper_sig=args.tamper_sig,
        old_seq=args.old_seq
    )


if __name__ == "__main__":
    main()

