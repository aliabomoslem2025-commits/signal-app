package org.thoughtcrime.securesms.registration.local

import android.content.Context
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Per-install device enrollment proof. Private key is non-exportable and
 * generated in Android Keystore; the admin only receives the public key.
 */
class LocalDeviceAuthKeyStore(private val context: Context) {
  private val alias = "signal.lan.device.auth.p256.v1"

  fun androidId(): String = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    ?.takeIf { it.isNotBlank() } ?: error("Android device ID unavailable")

  fun getOrCreateKeyPair(): KeyPair {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    store.getCertificate(alias)?.let { cert ->
      val privateKey = store.getKey(alias, null) as? PrivateKey
        ?: error("Approved device Keystore key is missing")
      return KeyPair(cert.publicKey, privateKey)
    }
    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    generator.initialize(
      KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
        .build()
    )
    return generator.generateKeyPair()
  }

  fun publicKeyPem(): String {
    val bytes = Base64.encodeToString(getOrCreateKeyPair().public.encoded, Base64.NO_WRAP)
    return "-----BEGIN PUBLIC KEY-----\n$bytes\n-----END PUBLIC KEY-----"
  }

  private fun sign(message: String): String {
    val signature = Signature.getInstance("SHA256withECDSA")
    signature.initSign(getOrCreateKeyPair().private)
    signature.update(message.toByteArray(Charsets.UTF_8))
    return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
  }

  fun signChallenge(id: String, phone: String, nonce: String): String =
    sign("signal-local-auth-v1\n$id\n$phone\n$nonce")

  fun signCompletion(id: String, phone: String, nonce: String, code: String): String {
    require(code.length == 6 && code.all { it in '0'..'9' })
    return sign("signal-local-auth-complete-v1\n$id\n$phone\n$nonce\n$code")
  }
}
