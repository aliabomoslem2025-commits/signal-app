# Local LAN client integration status

The `feature/local-lan-auth` branch contains the first Android client integration for the local device-authentication API.

## Implemented in the branch

- `LocalDeviceKeyManager` creates a per-install P-256 signing key in Android Keystore and reads `Settings.Secure.ANDROID_ID`.
- `AppRegistrationNetworkController` requests a LAN challenge, signs it, obtains the one-time compatibility code over HTTPS, and submits that code through the new local-auth API.
- `VerificationCodeViewModel` treats the local-auth session as a distinct flow, avoids requesting SMS/voice transport, and inserts the returned code into the existing verification-code entry flow.
- `LocalServerConfigStore` loads and validates the bundled `server-config.json` and provides persistence hooks for runtime configuration.

## Current limits that must be closed before production

- The public key must be pre-registered in the admin dashboard. The app branch does not yet expose a dedicated Settings screen to display/export the enrollment payload.
- The config store has no user-facing Settings editor/import/export screen yet. The network layer loads the config when its dependency module is constructed, so changing a saved config requires recreating network dependencies or restarting the app.
- The configured server endpoint trust chain must be trusted by Signal's configured trust store; the app does not yet provide certificate-CA enrollment/import.
- The old SMS retriever implementation and its dependency remain in the source tree, even though the local registration route does not request SMS.
- A separate app-specific PIN has not been implemented. Signal's existing screen lock delegates to the Android device credential; it is not a custom PIN owned by this app.
- CDN/storage, calls, background delivery/push, and other remote dependencies still need LAN implementations and endpoint wiring.

## Runtime config

Edit `app/src/main/assets/server-config.json` before building this branch to point to the LAN deployment. Do not put admin bearer tokens, private keys, or other secrets in this file. The current bundled values are examples and are not production endpoints.

This branch is not yet a fully validated offline/LAN release. Build, registration, multi-device, messaging, attachment, background-delivery, and calling tests are still required.
