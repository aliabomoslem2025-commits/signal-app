/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.thoughtcrime.securesms.registration.localauth

import android.content.Context
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64 as JavaBase64

/**
 * Creates a per-install ECDSA identity whose private key is generated and retained by Android Keystore.
 *
 * The Android ID is only an administrator-managed lookup value. It is not used as a password or signing secret.
 */
object LocalDeviceKeyManager {
  private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
  private const val KEY_ALIAS = "signal-local-device-auth-p256-v1"

  data class DeviceIdentity(
    val androidId: String,
    val publicKeyBase64: String
  )

  @Synchronized
  fun getOrCreateIdentity(context: Context): DeviceIdentity {
    val appContext = context.applicationContext
    val androidId = Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID)
      ?.takeIf { it.isNotBlank() }
      ?: throw IllegalStateException("Android ID is unavailable on this device")

    val keyStore = loadKeyStore()
    if (!keyStore.containsAlias(KEY_ALIAS)) {
      val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
      val parameters = KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN
      )
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
        .build()
      generator.initialize(parameters)
      generator.generateKeyPair()
    }

    val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
      ?: throw IllegalStateException("Android Keystore public key is missing")

    return DeviceIdentity(
      androidId = androidId,
      publicKeyBase64 = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
    )
  }

  /**
   * Signs the raw nonce bytes represented by the server's Base64URL challenge.
   * The returned signature is Base64URL without padding, matching the server endpoint contract.
   */
  @Synchronized
  fun signChallenge(context: Context, nonceBase64Url: String): String {
    getOrCreateIdentity(context)
    val keyStore = loadKeyStore()
    val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
      ?: throw IllegalStateException("Android Keystore private key is missing")

    val nonce = JavaBase64.getUrlDecoder().decode(nonceBase64Url)
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(privateKey)
    signer.update(nonce)
    return JavaBase64.getUrlEncoder().withoutPadding().encodeToString(signer.sign())
  }

  @Synchronized
  fun deleteIdentity() {
    loadKeyStore().deleteEntry(KEY_ALIAS)
  }

  private fun loadKeyStore(): KeyStore {
    return KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
  }
}
