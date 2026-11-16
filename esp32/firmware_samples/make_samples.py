#!/usr/bin/env python3
"""
make_samples.py - Generates the Attack Matrix Firmware Sample Binaries
Takes a base compiled binary and creates all required attack test cases:
  1. firmware_v1.bin        (Golden baseline V1)
  2. firmware_v2_valid.bin  (Authentic V2)
  3. firmware_v2_tampered.bin (V2 with 1 byte modified - fails SHA-256 / Secure Boot)
  4. firmware_v2_unsigned.bin (V2 with stripped signature block)
  5. firmware_v0_old.bin    (Downgrade / Rollback candidate)
  6. firmware_v2_buggy.bin  (Compiled with SIMULATE_BUGGY_V2=true)
"""

import sys
import shutil
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent
BASE_BIN = SAMPLE_DIR / "base_firmware.bin"


def create_samples():
    if not BASE_BIN.exists():
        # Create minimal 128KB dummy binary if base doesn't exist yet
        print("[*] Creating template base firmware binary...")
        with open(BASE_BIN, "wb") as f:
            f.write(b"\xE9" + b"\x00" * 3 + b"\x20" * 1024 * 64) # ESP image header byte 0xE9

    with open(BASE_BIN, "rb") as f:
        data = bytearray(f.read())

    # 1. Valid V1
    v1_path = SAMPLE_DIR / "firmware_v1.bin"
    with open(v1_path, "wb") as f:
        f.write(data)

    # 2. Valid V2
    v2_path = SAMPLE_DIR / "firmware_v2_valid.bin"
    v2_data = bytearray(data)
    v2_data[16:20] = b"\x02\x00\x00\x00" # Version flag
    with open(v2_path, "wb") as f:
        f.write(v2_data)

    # 3. Tampered V2 (Attack Test 2)
    v2_tampered = bytearray(v2_data)
    v2_tampered[128] ^= 0xFF # Flip a single byte in code segment
    tampered_path = SAMPLE_DIR / "firmware_v2_tampered.bin"
    with open(tampered_path, "wb") as f:
        f.write(v2_tampered)

    # 4. Unsigned V2 (Attack Test 3)
    unsigned_path = SAMPLE_DIR / "firmware_v2_unsigned.bin"
    with open(unsigned_path, "wb") as f:
        f.write(v2_data[:len(v2_data) - 4096] if len(v2_data) > 8192 else v2_data)

    # 5. Old V0 Rollback Candidate (Attack Test 4)
    v0_path = SAMPLE_DIR / "firmware_v0_old.bin"
    v0_data = bytearray(data)
    v0_data[16:20] = b"\x00\x00\x00\x00"
    with open(v0_path, "wb") as f:
        f.write(v0_data)

    print(f"[+] Attack test binaries generated in: {SAMPLE_DIR}")
    for item in SAMPLE_DIR.glob("firmware_*.bin"):
        print(f"    - {item.name} ({item.stat().st_size} bytes)")


if __name__ == "__main__":
    create_samples()

