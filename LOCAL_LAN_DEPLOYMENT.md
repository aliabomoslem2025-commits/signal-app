# Signal LAN deployment and enrollment

This branch is customized for a private Signal-compatible deployment. The app's LAN registration flow is enabled by default and fails closed: it does not fall back to public Signal SMS or voice verification when local authentication is unavailable.

## Enrollment order

1. Deploy the Go local-auth sidecar and the Java Signal Server. Configure the Java process with `LOCAL_AUTH_ONLY=true`, the internal HTTPS sidecar URL, and the same internal bearer secret used by the sidecar.
2. Place the dashboard behind a trusted HTTPS reverse proxy. Set the exact browser origin in `LOCAL_AUTH_ALLOWED_ORIGINS`.
3. Open the Android app's phone-number registration screen and tap **Local server setup** before submitting the number. Import the completed `server-config.json` and the private CA certificate that signs every configured HTTPS service.
4. On that same pre-registration setup screen, choose **Copy device enrollment information**. The app creates an ECDSA P-256 key in Android Keystore and copies only the Android ID and public key. The private key never leaves the device.
5. In the dashboard, create the E.164 phone-number record, select it, and enroll the copied Android ID + public key. Do not enroll a public key received through an untrusted channel.
6. Return to the app, enter the same phone number, and continue. The app sends the phone number and Android ID to the local-auth service, signs its challenge with Android Keystore, receives the six-digit code over HTTPS, fills the registration code field, and completes the normal Signal account registration using the one-time ticket.
7. After registration, an optional app-local PIN can be configured under **Settings → Local Server → Application PIN**. This PIN only locks the app locally; it is not the Signal account/SVR PIN and is never sent to the server.

For a second device, repeat steps 3–5 for the additional device and enroll its own Android ID/public key. Never copy a device private key from another installation.

## Endpoint configuration

The app loads `app/src/main/assets/server-config.json` as its initial template. Administrators can import/edit/export the same JSON under **Local server setup**. Saved values are stored in app-private preferences. Saving the file resets the existing network dependency graph and reopens connections using the new configuration.

- `localAuthApiUrl`: Go local-auth sidecar public HTTPS base URL.
- `services.signal`: Signal REST/WebSocket API base URL.
- `services.storage`: Signal storage-service base URL.
- `services.cdn0`, `cdn2`, `cdn3`: attachment/CDN API bases.
- `services.cdsi`: contact-discovery service base.
- `services.svr2`: secure value recovery v2 base.
- `services.sfu`: group-call SFU base. In LAN mode, group-call server selection uses this value.
- `services.turn`: TURN/TURNS URL. It is used as a static override only when both `turnUsername` and `turnCredential` are supplied. Use short-lived, rotated credentials; do not distribute a long-lived coturn secret in the app config.
- `services.svrb` and `services.attachments`: retained as deployment inventory/configuration slots. The current Android network factory does not create independent base clients from these two values; the corresponding server-side routes/services must be hosted consistently with the Signal API and CDN configuration.
- `trustedCaPem`: PEM-encoded private CA certificate used to validate the LAN HTTPS services. Hostname validation remains enabled.

The configuration rejects non-HTTPS service URLs (except loopback development), rejects a disabled certificate-validation flag, and requires a private CA certificate in LAN mode. Never use a permissive trust manager or disable hostname validation.

## Features that still require local infrastructure

The app and Signal Server are separate from the local-auth sidecar. A working URL in this file does not deploy a service.

| Capability | LAN requirement |
|---|---|
| Registration and device authorization | Go local-auth sidecar + Java ticket adapter + dashboard |
| Messaging | Signal Server REST/WebSocket services and their configured databases/queues |
| Attachments and media | Local CDN/object storage and Signal-compatible attachment routes |
| Contact discovery | Local CDSI-compatible service and its database |
| Group calling | Local SFU, configured in `services.sfu` and advertised/configured consistently by the server |
| 1:1 calling | Local calling API and TURN credentials; optionally use the static TURN override above |
| Background wake-up while the app is suspended | Local push/wakeup design or managed Android foreground/WebSocket strategy. FCM/APNs are external services and are not replaced by this authentication change. |

In a network with no public Internet, background notifications are not guaranteed by an open WebSocket alone: Android may suspend or terminate the app. Design and test the wake-up path for the exact device fleet and Android versions.

## Build and acceptance checks

Run the normal Android CI/build tasks with the repository's supported Android SDK/JDK. Before real use, verify on at least two physical devices on the isolated LAN:

- enrolled phone + Android ID + Keystore key succeeds;
- unregistered phone, mismatched Android ID, revoked device, disabled account, expired challenge, wrong signature and replayed ticket all fail;
- successful enrollment creates an ordinary Signal account and uploads its normal identity and prekeys;
- text, group, attachment, image, video and call flows work against only local endpoints;
- PIN set/change/remove, background lock, process restart and failed-attempt lockout work;
- message delivery is tested both while the recipient app is foregrounded and after Android suspends it.

A successful CI build is not a substitute for this two-device LAN acceptance test.
