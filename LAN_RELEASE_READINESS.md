# Signal Android — Self-hosted LAN operational status

> **Release decision: BLOCKED.** This branch reconstructs device-bound
> authentication, ntfy push and private LAN routing in the **new** Signal
> Android repository (Signal Android 8.36.2); it is **not** a certified
> production build. Static checks passing is insufficient to claim a working
> APK, a safe login system or end-to-end communications.

## What was implemented

- **No phone-number self-registration**. The number is created by a
  dashboard admin, who must explicitly enroll the Android handset's
  Android ID and P-256 public key. The private key remains in Android Keystore.
- **Mandatory local password factor:** after the local activation code auto-fills,
  the app requires a user-created password with confirmation on the first
  registration, and the existing password on every subsequent registration.
  The Go sidecar stores only a salted Argon2id hash and refuses to issue the
  signed one-time ticket without successful password validation. The
  administrator sees whether password setup is complete, not the password.
- The app requests a challenge from the Go local-auth service, signs it
  and receives a short-lived six-digit activation code **over private HTTPS,
  not via SMS**. The completion also requires the same Keystore key to sign
  `signal-local-auth-complete-v1\n{challengeId}\n{phone}\n{nonce}\n{code}`.
  A copied code alone does not authorize another handset.
- A non-enrolled handset receives HTTP 401/403 and the phone-entry screen
  displays the localized unauthorized device message, without exposing
  whether a number exists.
- Both newer registration and the old registration repository are connected
  to the local-auth protocol. The server must independently validate and
  consume the signed, single-use ticket, and reject recovery-password, public
  SMS/voice and old-device session fallbacks.
- `ntfy` is embedded as an Android foreground SSE subscriber. The authenticated
  Signal Server issues the private topic at `PUT /v1/accounts/ntfy`;
  only opaque `wake` notices arrive at ntfy. Normal Signal authenticated
  message retrieval handles E2E encrypted payloads. No separate ntfy app,
  Firebase token request or Firebase Messaging dependency is required.
- Build-time `app/src/main/assets/server-config.json` controls all core
  HTTPS LAN hostnames, private CA and cryptographic public parameters.
  Network service routing does not use upstream Signal DNS, Cloudflare,
  Google domain fronting or alternate upstream CDNs. No universal trust
  manager or TLS hostname verification bypass is installed.

## Before compiling or installing

1. Fill in `app/src/main/assets/server-config.json`:
   `services.signalApi`, `localAuthApi`, `ntfy`, `cdn0`,
   `cdn2`, `cdn3`, `storage`, `cdsi`, `svr2`,
   `callingSfu`, and `tus`. All must point at reachable,
   server-hosted **HTTPS** endpoints on the LAN. Placeholder `.lan`
   addresses are NOT automatically functional.
2. Insert your server's **real private CA PEM** in
   `security.trustedCaPem`. Issue certificates with SAN matching every
   hostname. Neither HTTP nor disabling certificate verification is
   permitted.
3. Set the four `crypto` values from the actual Signal Server key
   material: zkgroup, generic and backup server PUBLIC parameters, plus
   the SVR2 measurement, and the matching unidentified-sender trust roots.
   Do not reuse upstream public Signal production keys. Never insert any
   private key, publisher token, dashboard/admin token, auth sidecar internal
   secret, or SMS provider credential into this Android file.
4. Deploy **the matching server changes** in
   `aliabomoslem2025-commits/signal-server` including LAN-only
   registration and ntfy account APIs (PR #17 must pass review/CI). Set
   `LOCAL_AUTH_ONLY=true`, the sidecar internal URL, internal token,
   database, admin dashboard enrollment and HTTPS trust. The two client
   signatures and server canonical payloads MUST match. Do not deploy a
   new Android client against an unmodified upstream Signal Server.
5. Deploy local Redis, databases, attachment/CDN and TUS storage, coturn,
   calling SFU, CDSI, key transparency and SVR2/backup components required
   for the enabled features. The existence of a URL alone does not prove
   a service exists or is compatible.
6. Run `python3 scripts/lan_release_guard.py`, then
   `./gradlew ciRemote` and full Android compile/tests on your supported
   JDK/SDK, plus a **signed, minified release** build.
   The Gradle Release gate intentionally fails with empty CA or crypto
   fields; this is correct and must not be bypassed.

## How to enroll the first handset

From the pre-login phone-number screen open the overflow menu and select
**Local server and device enrollment**. Choose
**Copy device enrollment information**. The copied JSON contains
`androidId` and `publicKeyPem` only. The administrator verifies the
identity and E.164 ownership out-of-band, creates that number and
registers that handset's public key in the dashboard. Only one active
primary device may be enrolled per number on the companion Go sidecar.
Enter the phone number on the approved handset; it signs the challenge
and receives the server-generated activation code.

**Important:** Android's readable phone number and ANDROID_ID do *not*
prove the physical SIM card is inserted or that its number is owned by
this handset. The current app proves the presence of the enrolled Android
Keystore key, **not live SIM possession**. If your requirement is that SIM
A must physically remain in handset A when activating, integrate an
independently verified carrier/SMS-to-that-SIM factor using a private
GSM modem or carrier verification. No such SMS gateway has been deployed
and SMS was deliberately disabled.

## Security and operational acceptance tests

A release must pass ALL of these on two actual Android phones connected
to an isolated LAN with WAN blocked:

| Test | Expected |
|---|---|
| Registered phone A on approved handset A | Only A receives and completes local activation |
| Unknown phone number or B types A's number | No challenge/code; same generic unauthorized UI |
| B spoofs A's Android ID | Different Keystore private key fails ECDSA verification |
| B observes/copies A's activation code | Second ECDSA completion proof fails |
| A's first sign-in after local activation | User must create and confirm a personal password |
| A signs out and signs in again | Device approval, auto-filled code and personal password are all required |
| A uses the wrong password five times | Challenge is rejected; new activation required |
| Admin revokes A, enrolls B | Old challenges, tickets and new activation rejected |
| Two devices send encrypted text/groups/reactions/receipts | Normal E2E Signal delivery, no data in ntfy |
| App background, Wi-Fi loss, airplane mode, reboot, Doze | Automatic ntfy reconnect or documented OS limitation |
| Attachment uploads and downloads, resume, thumbnails, backup restore | Correct auth, checksum, range support, no loss |
| Voice/video calls + TURN/SFU on isolated network | Audio, video and reconnect across both devices |
| Wrong CA, expired certificate or wrong hostname | TLS connection refused; no public fallback |
| WAN packet capture | No unauthorized traffic to public Signal/Google/Firebase/Stripe endpoints |
| Account suspension / device and server-session revocation | Existing device credentials revoked on Signal Server, not only local-auth tickets |

## Remaining blockers / caveats

- **Full Android CI** on the recreated repository has not yet produced
  an independently reviewed successful Gradle compile or test report.
  A small GitHub Actions LAN source-only gate is not a replacement.
- Remaining features in the upstream Android code use Google Play
  Services/Maps, billing, payment, phone hints, public key transparency
  and the libsignal native network's `PRODUCTION` environment for some
  specialized functions. Additional component-level isolation/replacement
  is required for a **zero-public-network deployment**.
- Embedded ntfy requires a reachable private ntfy server with topic read
  authorization correctly configured. Do not expose topics publicly.
  Android system power restrictions can prevent background foreground-
  service starts after a force-stop; no app can universally bypass them.
- `signal-server` local-auth revocation prevents *new* registration
  but does **not** by itself invalidate a previously authenticated Signal
  session. Full device/session revocation must be completed server-side.
- The older client number-change and account restore screens need
  end-to-end LAN-specific product tests and server approval workflows.
- Materially changing the Signal protocol or crypto to "make it work"
  without test vectors and external security review is unsafe.

The branch intentionally remains **Draft** until all tests above pass.
