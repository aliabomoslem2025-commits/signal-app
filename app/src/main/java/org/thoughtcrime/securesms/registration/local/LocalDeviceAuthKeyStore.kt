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
 * Owns the non-exportable per-install ECDSA P-256 key used to prove that a pre-enrolled Android device is present.
 * Only the public key may be copied into the LAN administration dashboard.
 */
class LocalDeviceAuthKeyStore(context: Context) {
  private val appContext = context.applicationContext

  companion object {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "signal.local.device.auth.p256.v1"
  }

  fun androidId(): String {
    return Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID)
      ?.takeIf { it.isNotBlank() }
      ?: throw IllegalStateException("Android ID is unavailable on this device")
  }

  fun getOrCreateKeyPair(): KeyPair {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val existing = keyStore.getCertificate(KEY_ALIAS)
    if (existing != null) {
      val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
        ?: throw IllegalStateException("Android Keystore private key is unavailable")
      return KeyPair(existing.publicKey, privateKey)
    }

    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
    generator.initialize(
      KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
      )
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
        .build()
    )
    return generator.generateKeyPair()
  }

  fun publicKeyPem(): String {
    val encoded = getOrCreateKeyPair().public.encoded
    val body = Base64.encodeToString(encoded, Base64.NO_WRAP)
    return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
  }

  fun signCanonicalChallenge(challengeId: String, phone: String, nonceBase64Url: String): String {
    val message = "signal-local-auth-v1\n$challengeId\n$phone\n$nonceBase64Url"
    val signature = Signature.getInstance("SHA256withECDSA")
    signature.initSign(getOrCreateKeyPair().private)
    signature.update(message.toByteArray(Charsets.UTF_8))
    return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
  }
}
