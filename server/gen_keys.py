#!/usr/bin/env python3
"""
gen_keys.py - Cryptographic Key & Certificate Generator for Secure OTA
Generates:
  1. Root CA key and self-signed certificate (ca.key, ca.crt)
  2. Server key and certificate signed by CA with SANs (server.key, server.crt)
  3. Client key and certificate for mTLS device authentication (client.key, client.crt)
  4. RSA Keypair for SUIT firmware manifest signing (firmware_sign_priv.pem, firmware_sign_pub.pem)
  5. C-header files ready to embed into Arduino firmware (ca_cert.h, client_cert.h, firmware_pubkey.h)
"""

import os
import sys
import socket
import datetime
import ipaddress
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[!] 'cryptography' library not found.")
    print("    Install via: pip install -r requirements.txt")
    sys.exit(1)


def get_local_ip():
    """Detect local LAN IP for Subject Alternative Name (SAN)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually make a connection; extracts routing interface
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def generate_rsa_key(key_size=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def save_private_key(key, filepath):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filepath, 'wb') as f:
        f.write(pem)
    return pem


def save_public_key(key, filepath):
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, 'wb') as f:
        f.write(pem)
    return pem


def save_cert(cert, filepath):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(filepath, 'wb') as f:
        f.write(pem)
    return pem


def format_c_string(var_name, pem_bytes):
    """Format PEM bytes into a C PROGMEM null-terminated string literal."""
    text = pem_bytes.decode('utf-8').replace('\r\n', '\n').strip()
    lines = text.split('\n')
    formatted = f'const char {var_name}[] PROGMEM = \n'
    for line in lines:
        formatted += f'  "{line}\\n"\n'
    formatted += ';\n'
    return formatted


def main():
    base_dir = Path(__file__).resolve().parent
    keys_dir = base_dir / "keys"
    keys_dir.mkdir(exist_ok=True)
    
    arduino_dir = base_dir.parent / "arduino" / "ota_client"
    arduino_dir.mkdir(parents=True, exist_ok=True)

    local_ip = get_local_ip()
    print(f"[*] Detected local LAN IP: {local_ip}")
    print(f"[*] Generating cryptographic assets in: {keys_dir}")

    # -------------------------------------------------------------
    # 1. ROOT CA
    # -------------------------------------------------------------
    print("[1/5] Generating Root CA (Authority for server & client certs)...")
    ca_key = generate_rsa_key(2048)
    save_private_key(ca_key, keys_dir / "ca.key")

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BTP Secure IoT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "BTP Root CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_ski, critical=False)
        .add_extension(ca_aki, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    ca_cert_pem = save_cert(ca_cert, keys_dir / "ca.crt")

    # -------------------------------------------------------------
    # 2. SERVER CERTIFICATE (TLS with SAN for IP + localhost)
    # -------------------------------------------------------------
    print(f"[2/5] Generating Server Certificate with SANs (localhost, 127.0.0.1, {local_ip})...")
    server_key = generate_rsa_key(2048)
    save_private_key(server_key, keys_dir / "server.key")

    san_list = [
        x509.DNSName("localhost"),
        x509.DNSName("ota-server.local"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
    except Exception:
        pass

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BTP Secure IoT"),
        x509.NameAttribute(NameOID.COMMON_NAME, local_ip),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(ca_aki, critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    save_cert(server_cert, keys_dir / "server.crt")

    # -------------------------------------------------------------
    # 3. CLIENT CERTIFICATE (mTLS Hardware Identity)
    # -------------------------------------------------------------
    print("[3/5] Generating Client Certificate for mTLS (ESP32-C6 device authentication)...")
    client_key = generate_rsa_key(2048)
    client_key_pem = save_private_key(client_key, keys_dir / "client.key")

    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BTP Secure IoT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ESP32C6-SMARTELEX-01"),
    ])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()), critical=False)
        .add_extension(ca_aki, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    client_cert_pem = save_cert(client_cert, keys_dir / "client.crt")

    # -------------------------------------------------------------
    # 4. FIRMWARE SIGNING KEYPAIR (SUIT / Manifest RSA-2048)
    # -------------------------------------------------------------
    print("[4/5] Generating Firmware Signing Keypair (SUIT manifest signature)...")
    fw_sign_key = generate_rsa_key(2048)
    save_private_key(fw_sign_key, keys_dir / "firmware_sign_priv.pem")
    fw_pub_pem = save_public_key(fw_sign_key, keys_dir / "firmware_sign_pub.pem")

    # -------------------------------------------------------------
    # 5. GENERATE C-HEADERS FOR ARDUINO CLIENT
    # -------------------------------------------------------------
    print("[5/5] Generating C-headers for Arduino client in arduino/ota_client/...")
    
    ca_header = f"""// AUTO-GENERATED - DO NOT EDIT MANUALLY
// CA Root Certificate to authenticate the OTA server
#pragma once
#include <Arduino.h>

{format_c_string('ROOT_CA_CERT', ca_cert_pem)}
"""
    with open(arduino_dir / "ca_cert.h", "w") as f:
        f.write(ca_header)

    client_header = f"""// AUTO-GENERATED - DO NOT EDIT MANUALLY
// Device Client Certificate and Private Key for mTLS (Track A Software fallback)
#pragma once
#include <Arduino.h>

{format_c_string('CLIENT_CERT', client_cert_pem)}
{format_c_string('CLIENT_KEY', client_key_pem)}
"""
    with open(arduino_dir / "client_cert.h", "w") as f:
        f.write(client_header)

    fw_pub_header = f"""// AUTO-GENERATED - DO NOT EDIT MANUALLY
// Public Key to verify SUIT Manifest Digital Signature
#pragma once
#include <Arduino.h>

{format_c_string('FIRMWARE_SIGN_PUBKEY', fw_pub_pem)}
"""
    with open(arduino_dir / "firmware_pubkey.h", "w") as f:
        f.write(fw_pub_header)

    print("\n[+] SUCCESS! All cryptographic keys, certificates, and C-headers generated:")
    print(f"    - Keys: {keys_dir}")
    print(f"    - Headers: {arduino_dir}")
    print(f"    - Target Device ID: ESP32C6-SMARTELEX-01")
    print(f"    - Server SAN IP:    {local_ip}")


if __name__ == "__main__":
    main()
