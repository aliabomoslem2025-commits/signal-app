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
for value in ("AndroidKeyStore", "SHA256withECDSA", "LocalDeviceAuthCanonical.challenge(", "LocalDeviceAuthCanonical.completion("):
    check(value in key, f"Missing Keystore proof {value}")
canonical = read("app/src/main/java/org/thoughtcrime/securesms/registration/local/LocalDeviceAuthCanonical.kt")
for value in ("signal-local-auth-v1", "signal-local-auth-complete-v1", "Invalid E.164 number", "Invalid activation code"):
    check(value in canonical, f"Missing canonical activation proof {value}")
check("libs.firebase.messaging" not in read("demo/registration/build.gradle.kts"), "The registration demo must not reintroduce Firebase")
demo_manifest = read("demo/registration/src/main/AndroidManifest.xml")
check("com.google.firebase" not in demo_manifest, "The registration demo manifest still declares Firebase")
check("persistCursor(topic, eventId)" in ntfy and "loadCursor(topic)" in ntfy, "ntfy should resume from persisted SSE message ID after restart")
check("localAuth.isCompletedSession(sessionId)" in controller, "Registration must verify completed signed session")
check("registerNtfyTopic()" in ntfy and "MessageFetchJob()" in ntfy, "ntfy must receive opaque wake and fetch Signal messages")
check("FirebaseMessaging" not in ntfy and "FirebaseApp" not in ntfy, "ntfy must not depend on Firebase")

network = read("app/src/main/java/org/thoughtcrime/securesms/push/SignalServiceNetworkAccess.kt")
check("val DNS: Dns = Dns.SYSTEM" in network, "System DNS required")
check("= uncensoredConfiguration" in network, "Public Signal fallback must be disabled")
check("LocalServerTrustStore(context)" in network, "Missing private CA trust")
check("CustomDns(\"1.1.1.1\")" not in network, "Public Cloudflare DNS must be absent")
check("LanDestinationPolicy(" in network and "destinationPolicy.permits(" in network, "Signal HTTP network requests must obey the LAN allowlist")
policy = read("app/src/main/java/org/thoughtcrime/securesms/push/LanDestinationPolicy.kt")
check("https" in policy and "authorities" in policy, "Missing explicit LAN HTTPS hostname + port policy")
check("instanceFollowRedirects = false" in client, "Local device-auth must not follow off-LAN HTTP redirects")
check("instanceFollowRedirects = false" in ntfy, "ntfy SSE subscriber must not follow off-LAN HTTP redirects")


gradle = read("app/build.gradle.kts")
check("lanDocument" in gradle and "Release blocked" in gradle, "Gradle must read LAN JSON and block unconfigured releases")
check("libs.firebase.messaging" not in gradle, "Firebase Messaging runtime dependency must be removed")
check("FirebaseTestLabTask" not in gradle, "Firebase Test Lab and gcloud integrations are not allowed in isolated LAN builds")
for deprecated in ("app/src/main/res/values/firebase_messaging.xml", "app/proguard/proguard-firebase-messaging.pro"):
    check(not (root / deprecated).exists(), f"Remove stale Firebase configuration from APK/build: {deprecated}")

check("firebase-messaging =" not in read("gradle/libs.versions.toml"), "Firebase Messaging version catalog entry remains")
check("LAN1." in read("app/src/main/java/org/thoughtcrime/securesms/registration/local/LocalDeviceAuthClient.kt"), "Signed LAN registration ticket required")

if errors:
    print("LAN static check FAILED:")
    for error in errors:
        print(" -", error)
    sys.exit(1)
print("LAN static check passed (does not certify compilation, backend, cryptography or devices).")
