#!/usr/bin/env python3
"""Inventory remaining cloud/Firebase/Google references; prints PATHS ONLY.

This is a manual remediation aid, not a pass/fail test. Do not print
credentials, API tokens, matching source lines or private URLs in CI logs.
"""
from collections import defaultdict
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
patterns = {
    "Firebase runtime APIs": r"com\\.google\\.firebase|FirebaseMessaging|FirebaseInstallations|FirebaseApp",
    "Google Play Services": r"com\\.google\\.android\\.gms|GoogleApiAvailability|getSignInClient",
    "Public Signal hosts": r"signal\\.org|signal\\.me|signal\\.art|signal\\.link|signal\\.app",
    "Cloud hosted vendors": r"cloudflare|googleapis|stripe\\.com|giphy|amazonaws|firebaseio",
    "Legacy SMS verification": r"SmsRetriever|SmsManager|requestSmsVerificationCode|sendSms|SmsCode",
}

files = subprocess.check_output(
    ["git", "ls-files", "--", "*.java", "*.kt", "*.kts", "*.xml", "*.toml", "*.properties"],
    cwd=root, text=True
).splitlines()
exclude = ("/test/", "/androidTest/", "src/test/", "benchmark", "screenshots/", ".github/")
print(f"Tracked matching source/config files: {len(files)}")
for category, raw in patterns.items():
    compiled = re.compile(raw, re.IGNORECASE)
    found = defaultdict(int)
    for rel in files:
        if rel.startswith(".github/") or any(x in rel for x in exclude):
            continue
        try:
            data = (root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        count = len(compiled.findall(data))
        if count:
            found[rel] = count
    print(f"\\n== {category} : {len(found)} files ==")
    for path, count in sorted(found.items(), key=lambda item: (-item[1], item[0]))[:55]:
        print(f"  {path} ({count} refs)")
    if len(found) > 55:
        print(f"  ... {len(found)-55} further files")
print("\\nFindings are an inventory, not a statement that every reference makes a public network request.")
