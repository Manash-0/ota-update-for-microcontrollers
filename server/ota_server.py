#!/usr/bin/env python3
"""
ota_server.py - Production-Grade HTTPS & mTLS Firmware Server with Transparency Log
Features:
  1. HTTPS TLS 1.2/1.3 transport security
  2. Dual Authorization Modes:
     - Standard: Checks 'X-Device-ID' HTTP header against allowlist (Baseline, spoofable)
     - mTLS Mode (--mtls): Hardware-verified mutual TLS via client certificates (Secure, non-spoofable)
  3. Hash-Chained Update Transparency Log:
     - Maintains tamper-evident audit log of all manifest and firmware distributions
  4. Endpoints:
     - GET /ota/manifest.cbor (SUIT RFC 9124 / COSE binary manifest)
     - GET /ota/manifest.json (Auditable JSON manifest)
     - GET /ota/firmware.bin  (Compiled binary)
     - GET /ota/log           (Inspect hash-chained transparency log)
     - Dynamic query attack triggers: ?attack=bad_magic, ?attack=corrupt_hash, etc.
"""

import sys
import os
import ssl
import json
import time
import socket
import hashlib
import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
FIRMWARE_DIR = BASE_DIR / "firmware"
LOG_FILE = BASE_DIR / "transparency_log.json"

ALLOWED_DEVICES = ["ESP32C6-SMARTELEX-01", "ESP32C6-DEV-001"]

# Global transparency log ledger
transparency_log = []


def init_transparency_log():
    global transparency_log
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, "r") as f:
                transparency_log = json.load(f)
            return
        except Exception:
            pass
    # Initialize Genesis Block
    genesis = {
        "index": 0,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": "GENESIS_LOG_INITIALIZATION",
        "device_id": "SYSTEM",
        "prev_hash": "0" * 64,
        "entry_hash": hashlib.sha256(b"GENESIS_TRANSPARENCY_LOG_BTP_ESP32C6").hexdigest()
    }
    transparency_log = [genesis]
    save_transparency_log()


def save_transparency_log():
    with open(LOG_FILE, "w") as f:
        json.dump(transparency_log, f, indent=2)


def append_transparency_log(action, device_id, auth_mode, client_ip, extra=None):
    prev_entry = transparency_log[-1]
    prev_hash = prev_entry["entry_hash"]
    
    entry = {
        "index": len(transparency_log),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": action,
        "device_id": device_id,
        "auth_mode": auth_mode,
        "client_ip": client_ip,
        "details": extra or {},
        "prev_hash": prev_hash
    }
    
    serialized = json.dumps(entry, sort_keys=True).encode("utf-8")
    entry["entry_hash"] = hashlib.sha256(serialized).hexdigest()
    transparency_log.append(entry)
    save_transparency_log()
    print(f"[*] [Transparency Log] Entry #{entry['index']} chained ({entry['action']} - {device_id})")


class SecureOTAHandler(BaseHTTPRequestHandler):
    server_version = "BTP-SecureOTA/2.0"

    def authenticate_client(self):
        """
        Validates client identity via mTLS certificate if provided,
        otherwise falls back to X-Device-ID header.
        Returns: (authenticated: bool, device_id: str, auth_mode: str)
        """
        # 1. Check if mTLS client certificate was presented
        peercert = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
        if peercert:
            # Extract CommonName from peer certificate subject
            subject = dict(x[0] for x in peercert.get('subject', []))
            cn = subject.get('commonName')
            if cn in ALLOWED_DEVICES:
                return True, cn, "mTLS_CERTIFICATE"
            else:
                return False, cn or "UNKNOWN_CERT", "mTLS_CERTIFICATE"

        # 2. Check X-Device-ID HTTP header (Legacy/Baseline Mode)
        device_id = self.headers.get("X-Device-ID")
        if device_id in ALLOWED_DEVICES:
            return True, device_id, "X-Device-ID_HEADER"
        elif device_id:
            return False, device_id, "X-Device-ID_HEADER"

        # No identity provided
        return False, "ANONYMOUS", "NONE"

    def do_GET(self):
        client_ip = self.client_address[0]
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)
        attack_type = query.get("attack", [None])[0]

        # Authenticate client
        auth_ok, device_id, auth_mode = self.authenticate_client()

        # Handle Attack Matrix Test 9: Unauthorized Device ID
        if not auth_ok:
            print(f"[!] Access DENIED for unauthorized client ({device_id}) via {auth_mode} from {client_ip}")
            append_transparency_log("ACCESS_DENIED_UNAUTHORIZED", device_id, auth_mode, client_ip, {"path": path})
            body = json.dumps({
                "status": "DENIED",
                "error": "Device ID unauthorized or invalid certificate",
                "device_id": device_id
            }).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        print(f"[+] Authenticated request from '{device_id}' ({auth_mode}) for path: {path}")

        # -------------------------------------------------------------
        # Endpoint: Transparency Log Audit
        # -------------------------------------------------------------
        if path == "/ota/log":
            data = json.dumps(transparency_log, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        # -------------------------------------------------------------
        # Endpoint: SUIT CBOR Manifest
        # -------------------------------------------------------------
        if path in ("/ota/manifest.cbor", "/ota/manifest"):
            manifest_path = BASE_DIR / "manifest.cbor"
            
            # If dynamic attack parameter requested, rebuild on the fly
            if attack_type:
                print(f"[!] Dynamic Attack Mode Triggered: {attack_type}")
                fw_sample = FIRMWARE_DIR / "firmware_v2.bin"
                from build_manifest import build_manifest
                build_manifest(
                    bin_path=fw_sample,
                    priv_key_path=KEYS_DIR / "firmware_sign_priv.pem",
                    output_dir=BASE_DIR,
                    seq_num=2,
                    corrupt_hash=(attack_type == "corrupt_hash"),
                    bad_magic=(attack_type == "bad_magic"),
                    tamper_sig=(attack_type == "tamper_sig"),
                    old_seq=(attack_type == "old_seq")
                )

            if not manifest_path.exists():
                self.send_error(404, "Manifest file not found. Run build_manifest.py first.")
                return

            with open(manifest_path, "rb") as f:
                data = f.read()

            append_transparency_log("MANIFEST_SERVED", device_id, auth_mode, client_ip, {
                "format": "CBOR",
                "bytes": len(data),
                "attack_flag": attack_type
            })

            self.send_response(200)
            self.send_header("Content-Type", "application/cbor")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        # -------------------------------------------------------------
        # Endpoint: Manifest JSON (Debug & Fallback)
        # -------------------------------------------------------------
        if path == "/ota/manifest.json":
            manifest_json_path = BASE_DIR / "manifest.json"
            if not manifest_json_path.exists():
                self.send_error(404, "manifest.json not found")
                return

            with open(manifest_json_path, "rb") as f:
                data = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        # -------------------------------------------------------------
        # Endpoint: Firmware Binary
        # -------------------------------------------------------------
        if path == "/ota/firmware.bin":
            fw_path = FIRMWARE_DIR / "firmware_v2.bin"
            if not fw_path.exists():
                self.send_error(404, "firmware_v2.bin not found in firmware/ folder.")
                return

            with open(fw_path, "rb") as f:
                fw_data = f.read()

            fw_hash = hashlib.sha256(fw_data).hexdigest()
            append_transparency_log("FIRMWARE_DOWNLOADED", device_id, auth_mode, client_ip, {
                "size_bytes": len(fw_data),
                "sha256": fw_hash
            })

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(fw_data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(fw_data)
            return

        # Unknown route
        self.send_error(404, f"Path not found: {path}")


def run_server(port=8443, mtls=False):
    os.chdir(BASE_DIR)
    init_transparency_log()
    server_addr = ("0.0.0.0", port)
    httpd = HTTPServer(server_addr, SecureOTAHandler)

    cert_file = KEYS_DIR / "server.crt"
    key_file = KEYS_DIR / "server.key"
    ca_file = KEYS_DIR / "ca.crt"

    if not cert_file.exists() or not key_file.exists():
        print(f"[!] TLS certificates missing in {KEYS_DIR}.")
        print("    Please run: python gen_keys.py first.")
        sys.exit(1)

    # Configure TLS Context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    if mtls:
        print("[*] MODE: Mutual TLS (mTLS) ENFORCED - Client certificate REQUIRED")
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_file))
    else:
        print("[*] MODE: Standard HTTPS with optional mTLS / X-Device-ID header check")
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_verify_locations(cafile=str(ca_file))

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"\n=======================================================")
    print(f"  BTP Secure OTA Firmware Server Online")
    print(f"  URL: https://0.0.0.0:{port}/")
    print(f"  Allowed Devices: {ALLOWED_DEVICES}")
    print(f"  mTLS Enforced:   {mtls}")
    print(f"  Audit Log:       https://localhost:{port}/ota/log")
    print(f"=======================================================\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure OTA Server for ESP32-C6")
    parser.add_argument("--port", type=int, default=8443, help="HTTPS Port (default 8443)")
    parser.add_argument("--mtls", action="store_true", help="Enforce strict mTLS client certificate verification")
    args = parser.parse_args()

    run_server(port=args.port, mtls=args.mtls)
