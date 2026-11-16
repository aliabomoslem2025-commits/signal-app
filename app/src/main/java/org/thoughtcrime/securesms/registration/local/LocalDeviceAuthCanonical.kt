package org.thoughtcrime.securesms.registration.local

/**
 * Shared, deterministic encoding of the Go local-auth wire protocol.
 *
 * These exact UTF-8 bytes are authenticated with SHA256withECDSA by the
 * handset's non-exportable Android Keystore P-256 private key.
 * Any format change requires a coordinated server protocol update.
 */
internal object LocalDeviceAuthCanonical {
  private val phonePattern = Regex("^\\+[1-9][0-9]{7,14}$")

  fun challenge(id: String, phone: String, nonce: String): ByteArray {
    require(phonePattern.matches(phone)) { "Invalid E.164 number" }
    return "signal-local-auth-v1\n$id\n$phone\n$nonce".toByteArray(Charsets.UTF_8)
  }

  fun completion(id: String, phone: String, nonce: String, code: String): ByteArray {
    require(phonePattern.matches(phone)) { "Invalid E.164 number" }
    require(code.length == 6 && code.all { it in '0'..'9' }) { "Invalid activation code" }
    return "signal-local-auth-complete-v1\n$id\n$phone\n$nonce\n$code".toByteArray(Charsets.UTF_8)
  }
}
