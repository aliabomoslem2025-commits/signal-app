# Local LAN client authentication and endpoint configuration

> Status: design contract for the `local-lan-auth` branch. The configuration format below is a proposed schema; the app does not load it at runtime yet.

## Login behavior

The phone-number entry screen remains the starting point. When the user taps Continue, the app:

1. Normalizes the phone number to E.164.
2. Reads `Settings.Secure.ANDROID_ID`.
3. Uses a per-installation signing key generated in Android Keystore when device-key enrollment is enabled.
4. Calls the server's local-auth session endpoint over TLS.
5. Receives a short-lived session ID and one-time verification value.
6. Automatically fills/submits the value and continues through the existing Signal account-registration operation.

The app must not use Android SMS Retriever, SMS permissions, SMS transport, or voice-call verification for this flow. Do not remove unrelated legacy database and backup code needed to preserve old message history.

Android ID is not a secret and can change after factory reset or app-signing/user changes. It should be treated as an enrollment identifier, not as the sole cryptographic proof of device ownership. The Keystore signing key should be the proof when the server has a registered public key for the device.

## Optional PIN

The new local-app PIN is separate from Signal's existing SVR / Registration Lock PIN.

- Add a setting to enable, change, and disable the local-app PIN.
- Require successful device authentication before setting or changing the PIN.
- Store only a salted verifier; do not log or persist plaintext PINs.
- Keep the local unlock gate usable while the LAN server is temporarily unavailable.
- Add retry delays and a recovery/reset flow.
- Do not alter or remove the existing SVR PIN backup/restore behavior.

## Endpoint file

The proposed runtime file is named `local-network-config.json`. It should be imported/exported from an advanced Server Configuration section in Settings. The default values should be populated from the build's current configuration, while an administrator can supply LAN URLs.

Example schema:

```json
{
  "schemaVersion": 1,
  "environment": "lan",
  "service": {
    "baseUrl": "https://signal-server.lan",
    "websocketUrl": "wss://signal-server.lan"
  },
  "storage": {
    "baseUrl": "https://signal-storage.lan"
  },
  "cdn": {
    "0": "https://signal-cdn.lan",
    "2": "https://signal-cdn2.lan",
    "3": "https://signal-cdn3.lan"
  },
  "cdsi": {
    "baseUrl": "https://signal-cdsi.lan"
  },
  "svr2": {
    "baseUrl": "https://signal-svr2.lan"
  },
  "svrb": {
    "baseUrl": "https://signal-svrb.lan"
  },
  "secureStorage": {
    "baseUrl": "https://signal-secure-storage.lan"
  },
  "keyTransparency": {
    "baseUrl": "https://signal-key-transparency.lan"
  },
  "attachments": {
    "uploadBaseUrl": "https://signal-attachments.lan"
  },
  "calling": {
    "sfuBaseUrl": "https://signal-sfu.lan",
    "turnBaseUrl": "https://signal-turn.lan"
  },
  "registration": {
    "mode": "local-enrollment",
    "localAuthBaseUrl": "https://signal-server.lan/v1/local-auth"
  },
  "tls": {
    "certificateProfile": "lan-ca"
  }
}
```

The app must validate the complete configuration before applying it:
- Require HTTPS/WSS except an explicitly enabled development profile.
- Reject unknown schema versions and malformed URLs.
- Never disable hostname verification or certificate validation.
- Use a trusted LAN CA or a certificate pinning mechanism with rotation support.
- Apply the same base configuration to REST, WebSocket, CDN, attachment, backup, and calling modules where applicable.
- Show the currently active server profile and provide an administrator-controlled import/reset action.

The final implementation must trace every URL used by the app. Changing only `SIGNAL_URL` is insufficient: the current client also has separate Storage, CDN, CDSI, SVR, Calling, attachment, backup, and other service endpoints.

## Tests required before rollout

- Correct number + enrolled device.
- Correct number + different Android ID.
- Correct Android ID + different number.
- Missing/invalid/revoked device key.
- Expired or replayed local session.
- Network interruption between session creation, verification, and account registration.
- PIN success, failure, lockout, reset, and offline unlock.
- Invalid configuration, untrusted TLS certificate, and endpoint switch.
- Online message delivery and offline queue recovery after reconnect.
