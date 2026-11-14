# Local LAN client integration status

The `local-lan-auth` branch contains the Android-side integration for a privately managed Signal deployment.

## Implemented in this branch

- Each app installation creates a P-256 signing key in Android Keystore. The private key is non-exportable; `Settings.Secure.ANDROID_ID` is only an administrator-managed lookup value.
- Before account registration, the phone-number screen exposes **Enroll device**. It exports the E.164 phone number, Android ID, device display name and X.509 public key as JSON for the administrator. The private key is never included.
- `AppRegistrationNetworkController` uses `POST /v1/local-auth/challenge`, signs the returned nonce, calls `/verify`, retrieves the compatibility code over HTTPS and submits it to `/submit-code`.
- The local code is consumed by the existing verification UI. The registration controller only accepts a local registration session after the code has been submitted successfully.
- The legacy SMS Retriever receiver/listener has been removed from the local branch. The registration flow does not request SMS or voice delivery.
- An optional application PIN is implemented separately from the Signal account/SVR PIN. Its verifier is HMAC-protected with an Android Keystore key and is checked locally.
- `LocalNetworkSettingsActivity` allows the user/operator to edit, validate, copy and reset `server-config.json`; it also manages the optional PIN and exports enrollment information after registration.
- The app's Signal service trust store can add administrator-supplied private LAN CA certificates from `trustedCaPem`. TLS validation remains enabled.
- The app uses the configured LAN service/CDN/storage/CDSI/SVR2 addresses for the supported network configuration and no longer selects the public censorship-circumvention endpoints for some country codes.

## Configuration

Edit `app/src/main/assets/server-config.json` or import its JSON content in Settings > Local network. Provide the private CA PEM in `trustedCaPem` when the deployment certificate chains to a private CA. Keep `allowCleartext=false`, `validateCertificates=true` and `smsEnabled=false`.

The current endpoint model has fields for WebSocket, CDN, storage, CDSI, SVR2/SVRB, attachments, SFU and TURN. Not every module is yet dynamically routed from this JSON; in particular, the calling and some auxiliary service transports still require source-level wiring and infrastructure configuration. Restart the app after saving endpoint changes.

## Remaining production validation

This branch has not yet passed a fresh Android CI build after the latest local-auth changes and has not been tested against a running private LAN deployment. Full production readiness still requires:
- Android build, unit and instrumentation tests;
- signed challenge, code submission and account creation against the deployed server;
- two-device messaging, group, attachment and offline/foreground-delivery tests;
- replacement or deliberate exclusion of FCM/APNs for an isolated network;
- LAN media storage and calling infrastructure (SFU/TURN) if those features are required.

Do not treat this branch as a verified fully-offline production release until the above integration tests pass.
