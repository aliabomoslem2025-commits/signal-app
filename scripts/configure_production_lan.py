#!/usr/bin/env python3
"""Fail-closed installer for a real LAN APK build configuration.

Input must come from the *actual* deployed services and server's published
cryptographic parameters; this never manufactures fake URLs, keys or enclaves.
Example:
  python3 scripts/configure_production_lan.py \
    --services /secure/config/lan-services.json \
    --crypto /secure/config/signal-public-crypto.json \
    --ca /secure/pki/root-ca.pem
"""
import argparse
import base64
import json
import pathlib
import re
import ssl
from urllib.parse import urlsplit

FIELDS = (
    "signalApi", "localAuthApi", "ntfy", "cdn0", "cdn2", "cdn3",
    "storage", "cdsi", "svr2", "callingSfu", "tus"
)
CRYPTO_FIELDS = (
    "zkGroupServerPublicParams", "genericServerPublicParams",
    "backupServerPublicParams", "svr2MrEnclave"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--services", type=pathlib.Path, required=True)
    parser.add_argument("--crypto", type=pathlib.Path, required=True)
    parser.add_argument("--ca", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("app/src/main/assets/server-config.json"))
    args = parser.parse_args()

    services = json.loads(args.services.read_text(encoding="utf-8"))
    crypto = json.loads(args.crypto.read_text(encoding="utf-8"))
    if not isinstance(services, dict) or not isinstance(crypto, dict):
        raise SystemExit("Services and public crypto input must be JSON objects")

    missing = set(FIELDS) - set(services)
    if missing:
        raise SystemExit("Missing real HTTPS service URLs: " + ", ".join(sorted(missing)))

    normalized = {}
    for name in FIELDS:
        value = services[name]
        if not isinstance(value, str):
            raise SystemExit(f"{name}: must be an HTTPS URL string")
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username or
                parts.password or parts.query or parts.fragment or parts.path not in ("", "/")):
            raise SystemExit(f"{name}: a complete HTTPS origin without credentials is required")
        if (parts.hostname.endswith((".example", ".example.invalid", ".invalid")) or
                parts.hostname in ("localhost", "127.0.0.1") or
                "example" in parts.hostname):
            raise SystemExit(f"{name}: placeholder and loopback URLs are forbidden in production")
        normalized[name] = value.rstrip("/")

    missing_crypto = [field for field in CRYPTO_FIELDS if not isinstance(crypto.get(field), str) or len(crypto[field]) < 20]
    if missing_crypto:
        raise SystemExit("Missing server-generated cryptographic public parameters: " + ", ".join(missing_crypto))
    roots = crypto.get("unidentifiedSenderTrustRoots")
    if not isinstance(roots, list) or not roots or not all(isinstance(item, str) and len(item) > 20 for item in roots):
        raise SystemExit("Supply the Signal server's published unidentified sender trust roots")

    for field in ("zkGroupServerPublicParams", "genericServerPublicParams", "backupServerPublicParams"):
        try:
            base64.b64decode(crypto[field], validate=True)
        except Exception as exc:
            raise SystemExit(f"{field} must be actual Base64 public parameters") from exc

    pem = args.ca.read_text(encoding="utf-8")
    if "-----BEGIN CERTIFICATE-----" not in pem or "-----END CERTIFICATE-----" not in pem:
        raise SystemExit("A real trusted LAN certificate authority PEM is required")
    try:
        ssl.PEM_cert_to_DER_cert(pem)
    except ValueError as exc:
        raise SystemExit("Invalid LAN CA certificate PEM") from exc

    document = {
        "mode": "LOCAL_LAN",
        "localAuthOnly": True,
        "services": normalized,
        "security": {
            "requireHttps": True,
            "allowCleartext": False,
            "validateCertificates": True,
            "trustedCaPem": pem.strip(),
        },
        "crypto": {name: crypto[name] for name in CRYPTO_FIELDS} | {
            "unidentifiedSenderTrustRoots": roots
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"LAN production APK configuration validated and written to {args.output}")
    print("Now run scripts/lan_release_guard.py and your release build. Compile success is not an end-to-end service test.")


if __name__ == "__main__":
    main()
