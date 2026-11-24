#!/usr/bin/env python3
"""Static release checks for the custom Signal LAN fork (not a runtime certification)."""
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
errors = []
def check(condition, message):
    if not condition:
        errors.append(message)

def read(path):
    p = root / path
    if not p.is_file():
        errors.append(f"Required file missing: {path}")
        return ""
    return p.read_text(encoding="utf-8")

settings = json.loads(read("app/src/main/assets/server-config.json"))
check(settings.get("mode") == "LOCAL_LAN", "Must be LAN-only")
check(settings.get("localAuthOnly") is True, "Public registration must be disabled")
security = settings.get("security", {})
check(security.get("requireHttps") is True and security.get("validateCertificates") is True and security.get("allowCleartext") is False, "HTTPS / certificate verification must be enabled")
services = settings.get("services", {})
required = ["signalApi", "localAuthApi", "ntfy", "cdn0", "cdn2", "cdn3", "storage", "cdsi", "svr2", "callingSfu", "tus"]
for service in required:
    url = services.get(service, "")
    check(url.startswith("https://") and "@" not in url, f"{service} must be HTTPS and not contain embedded credentials")
for name in ("publisherToken", "adminToken", "internalToken", "secretKey", "privateKey"):
    check(name not in str(settings), f"Do not embed {name} in an APK")

android_ns = "{http://schemas.android.com/apk/res/android}"
manifest = ET.fromstring(read("app/src/main/AndroidManifest.xml"))
app = manifest.find("application")
check(app is not None and app.get(android_ns + "usesCleartextTraffic") == "false", "Disallow cleartext traffic")
services_in_manifest = {s.get(android_ns + "name"): s for s in manifest.findall(".//service")}
check(".push.NtfyPushService" in services_in_manifest, "Embedded ntfy service missing")
if ".push.NtfyPushService" in services_in_manifest:
    check(services_in_manifest[".push.NtfyPushService"].get(android_ns + "exported") == "false", "ntfy service must be private")
check(".gcm.FcmReceiveService" not in services_in_manifest, "FCM receiver is still registered")
permissions = {p.get(android_ns + "name") for p in manifest.findall("uses-permission")}
for p in ("android.permission.INTERNET", "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING", "android.permission.POST_NOTIFICATIONS", "android.permission.RECEIVE_BOOT_COMPLETED"):
    check(p in permissions, f"Missing Android permission {p}")

client = read("app/src/main/java/org/thoughtcrime/securesms/registration/local/LocalDeviceAuthClient.kt")
key = read("app/src/main/java/org/thoughtcrime/securesms/registration/local/LocalDeviceAuthKeyStore.kt")
controller = read("app/src/main/java/org/thoughtcrime/securesms/registration/v2/AppRegistrationNetworkController.kt")
ntfy = read("app/src/main/java/org/thoughtcrime/securesms/push/NtfyPushService.kt")
for value in ("signCompletion(", '"signature", signature', "LanDeviceNotAuthorizedException", "/v1/local-auth/complete"):
    check(value in client, f"Missing signed two-factor completion: {value}")
for value in ("AndroidKeyStore", "SHA256withECDSA", "signal-local-auth-v1", "signal-local-auth-complete-v1"):
    check(value in key, f"Missing Keystore proof {value}")
check("localAuth.isCompletedSession(sessionId)" in controller, "Registration must verify completed signed session")
check("registerNtfyTopic()" in ntfy and "MessageFetchJob()" in ntfy, "ntfy must receive opaque wake and fetch Signal messages")
check("FirebaseMessaging" not in ntfy and "FirebaseApp" not in ntfy, "ntfy must not depend on Firebase")
for transport in (client, ntfy):
    check("instanceFollowRedirects = false" in transport, "LAN auth and ntfy redirects must be disabled")
    check("openConnection(Proxy.NO_PROXY)" in transport, "LAN auth and ntfy must not use a system HTTP proxy")

network = read("app/src/main/java/org/thoughtcrime/securesms/push/SignalServiceNetworkAccess.kt")
check("val DNS: Dns = Dns.SYSTEM" in network, "System DNS required")
check("= uncensoredConfiguration" in network, "Public Signal fallback must be disabled")
check("LocalServerTrustStore(context)" in network, "Missing private CA trust")
check("CustomDns(\"1.1.1.1\")" not in network, "Public Cloudflare DNS must be absent")

gradle = read("app/build.gradle.kts")
check("lanDocument" in gradle and "Release blocked" in gradle, "Gradle must read LAN JSON and block unconfigured releases")
check("libs.firebase.messaging" not in gradle, "Firebase Messaging runtime dependency must be removed")
check("firebase-messaging =" not in read("gradle/libs.versions.toml"), "Firebase Messaging version catalog entry remains")
check("LAN1." in read("app/src/main/java/org/thoughtcrime/securesms/registration/local/LocalDeviceAuthClient.kt"), "Signed LAN registration ticket required")

if errors:
    print("LAN static check FAILED:")
    for error in errors:
        print(" -", error)
    sys.exit(1)
print("LAN static check passed (does not certify compilation, backend, cryptography or devices).")
