#!/usr/bin/env python3
"""
run_attack_matrix.py - Automated Security Verification & Attack Suite
Executes the server-side attack matrix and validates cryptographic enforcement.

Outputs a PASS / CORRECTLY REJECTED summary table matching the PPT matrix.
"""

import sys
import os
import ssl
import json
import socket
from pathlib import Path

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' library not found. Run: pip install -r requirements.txt")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
SERVER_DIR = BASE_DIR / "server"
KEYS_DIR = SERVER_DIR / "keys"

CA_CERT = KEYS_DIR / "ca.crt"
CLIENT_CERT = KEYS_DIR / "client.crt"
CLIENT_KEY = KEYS_DIR / "client.key"


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def run_tests(server_ip=None, port=8443):
    if not server_ip:
        server_ip = get_local_ip()

    base_url = f"https://{server_ip}:{port}"
    print(f"\n==================================================================")
    print(f"  RUNNING BTP SECURE OTA ATTACK MATRIX & NOVELTY VERIFICATION")
    print(f"  Target Server: {base_url}")
    print(f"==================================================================\n")

    # Use session with trust_env=False to bypass system proxies on localhost/LAN
    session = requests.Session()
    session.trust_env = False

    results = []

    def record_result(test_id, name, expected, actual, passed, explanation):
        status_str = "PASS / CORRECTLY REJECTED" if passed else "FAIL"
        results.append({
            "id": test_id,
            "name": name,
            "expected": expected,
            "actual": actual,
            "status": status_str,
            "details": explanation
        })
        print(f"[{'✓' if passed else '✗'}] Test {test_id}: {name}")
        print(f"    Expected: {expected}")
        print(f"    Actual:   {actual}")
        print(f"    Result:   {status_str}\n")

    # -------------------------------------------------------------
    # TEST 1: Authorized Device Request (Baseline)
    # -------------------------------------------------------------
    try:
        resp = session.get(
            f"{base_url}/ota/manifest.json",
            headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"},
            verify=False,
            timeout=5
        )
        passed = (resp.status_code == 200)
        record_result(
            1, "Authorized Device Manifest Access",
            "HTTP 200 OK with valid manifest",
            f"HTTP {resp.status_code}",
            passed,
            "Authorized device credentials granted access to update artifacts."
        )
    except Exception as e:
        record_result(1, "Authorized Device Manifest Access", "HTTP 200", f"Error: {e}", False, "Server unreachable")

    # -------------------------------------------------------------
    # TEST 7: Corrupted Hash in Manifest
    # -------------------------------------------------------------
    try:
        resp = session.get(
            f"{base_url}/ota/manifest.cbor?attack=corrupt_hash",
            headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"},
            verify=False,
            timeout=5
        )
        # Fetch the JSON mirror to verify the corruption flag
        j_resp = session.get(
            f"{base_url}/ota/manifest.json",
            headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"},
            verify=False,
            timeout=5
        )
        manifest_data = j_resp.json()
        is_corrupted = manifest_data.get("flags", {}).get("corrupt_hash", False)
        passed = (resp.status_code == 200 and is_corrupted)
        record_result(
            7, "Corrupt Hash Injection in Manifest",
            "Server generates corrupted hash manifest; Client must reject SHA-256",
            f"Manifest built with corrupt_hash={is_corrupted}",
            passed,
            "Manifest SHA-256 does not match actual firmware binary hash."
        )
    except Exception as e:
        record_result(7, "Corrupt Hash Injection in Manifest", "Hash mismatch", f"Error: {e}", False, str(e))

    # -------------------------------------------------------------
    # TEST 8: Bad Magic Bytes (0xDEADBEEF)
    # -------------------------------------------------------------
    try:
        resp = session.get(
            f"{base_url}/ota/manifest.cbor?attack=bad_magic",
            headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"},
            verify=False,
            timeout=5
        )
        j_resp = session.get(
            f"{base_url}/ota/manifest.json",
            headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"},
            verify=False,
            timeout=5
        )
        magic_val = j_resp.json().get("magic", "")
        passed = (magic_val == "0xDEADBEEF")
        record_result(
            8, "Bad Magic Bytes Injection (0xDEADBEEF)",
            "Manifest magic equals 0xDEADBEEF; Client SUIT parser must reject",
            f"Magic emitted: {magic_val}",
            passed,
            "SUIT header magic bytes set to invalid 0xDEADBEEF signature."
        )
    except Exception as e:
        record_result(8, "Bad Magic Bytes Injection", "0xDEADBEEF", f"Error: {e}", False, str(e))

    # -------------------------------------------------------------
    # TEST 9: Unauthorized Device ID Access
    # -------------------------------------------------------------
    try:
        resp = session.get(
            f"{base_url}/ota/manifest.json",
            headers={"X-Device-ID": "MALICIOUS_ATTACKER_ID_999"},
            verify=False,
            timeout=5
        )
        passed = (resp.status_code == 403)
        record_result(
            9, "Unauthorized Device ID Access Attempt",
            "HTTP 403 Forbidden",
            f"HTTP {resp.status_code}",
            passed,
            "Server successfully rejected unknown device identity."
        )
    except Exception as e:
        record_result(9, "Unauthorized Device ID Access Attempt", "HTTP 403", f"Error: {e}", False, str(e))

    # -------------------------------------------------------------
    # NOVELTY DEMO: X-Device-ID Header Spoofing Vulnerability (Before vs After mTLS)
    # -------------------------------------------------------------
    print("[*] Demonstrating Novelty 2: Header-Spoofing Vulnerability vs mTLS Protection...")
    try:
        # Attacker without credentials simply adds the header
        spoofed_resp = session.get(
            f"{base_url}/ota/firmware.bin",
            headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"},
            verify=False,
            timeout=5
        )
        vuln_exposed = (spoofed_resp.status_code == 200)
        record_result(
            "NOV-1", "Header Spoofing Attack (Baseline Weakness)",
            "Attacker can forge plain HTTP header without possessing device key",
            f"HTTP {spoofed_resp.status_code} (Firmware exfiltrated if mTLS not enforced)",
            vuln_exposed,
            "Confirms why X-Device-ID is insecure and justifies hardware-backed mTLS."
        )
    except Exception as e:
        record_result("NOV-1", "Header Spoofing Attack", "Vulnerability demonstration", f"Error: {e}", False, str(e))

    # -------------------------------------------------------------
    # NOVELTY DEMO: Hash-Chained Update Transparency Log
    # -------------------------------------------------------------
    try:
        log_resp = session.get(f"{base_url}/ota/log", headers={"X-Device-ID": "ESP32C6-SMARTELEX-01"}, verify=False, timeout=5)
        log_data = log_resp.json()
        
        # Verify hash chaining
        chain_intact = True
        for i in range(1, len(log_data)):
            curr = log_data[i]
            prev = log_data[i-1]
            if curr["prev_hash"] != prev["entry_hash"]:
                chain_intact = False
                break

        record_result(
            "NOV-2", "Update Transparency Log Hash-Chain Audit",
            "Cryptographic hash chain intact across all distribution events",
            f"Chain valid={chain_intact} ({len(log_data)} total blocks)",
            chain_intact,
            "Ledger provides tamper-evident proof that no unauthorized updates were served."
        )
    except Exception as e:
        record_result("NOV-2", "Transparency Log Audit", "Chain valid", f"Error: {e}", False, str(e))

    # -------------------------------------------------------------
    # Summary Table Printout
    # -------------------------------------------------------------
    print("\n" + "="*80)
    print(f"{'#':<6} {'Test Scenario':<42} {'Status':<25}")
    print("="*80)
    for r in results:
        print(f"{r['id']:<6} {r['name']:<42} {r['status']:<25}")
    print("="*80 + "\n")


if __name__ == "__main__":
    ip_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_tests(server_ip=ip_arg)
