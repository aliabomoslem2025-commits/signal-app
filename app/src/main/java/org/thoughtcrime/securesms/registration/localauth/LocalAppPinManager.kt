package org.thoughtcrime.securesms.registration.localauth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import java.security.MessageDigest

/**
 * Optional application-entry PIN, separate from Signal's account/SVR PIN.
 *
 * A device-bound HMAC key lives in Android Keystore, so the verifier stored in preferences cannot
 * be used for offline PIN guessing after merely copying the app's private preferences.
 */
object LocalAppPinManager {
  private const val PREFS = "local_application_pin"
  private const val KEY_SALT = "salt"
  private const val KEY_VERIFIER = "verifier"
  private const val KEY_FAILURES = "failures"
  private const val KEY_LOCKED_UNTIL = "locked_until"
  private const val KEYSTORE_ALIAS = "local-application-pin-hmac-v1"
  private const val MIN_PIN_LENGTH = 6
  private const val MAX_PIN_LENGTH = 12

  @Volatile
  private var unlockedForForeground: Boolean = false

  fun isEnabled(context: Context): Boolean {
    val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    return !prefs.getString(KEY_VERIFIER, null).isNullOrBlank() &&
      !prefs.getString(KEY_SALT, null).isNullOrBlank()
  }

  fun isUnlocked(): Boolean = unlockedForForeground

  fun lock() {
    unlockedForForeground = false
  }

  fun setPin(context: Context, pin: String): Boolean {
    if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH || pin.any { !it.isDigit() }) return false
    return try {
      val salt = ByteArray(32).also(SecureRandom()::nextBytes)
      val verifier = hmac(salt, pin)
      context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
        .putString(KEY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP))
        .putInt(KEY_FAILURES, 0)
        .putLong(KEY_LOCKED_UNTIL, 0L)
        .apply()
      unlockedForForeground = true
      true
    } catch (_: Exception) {
      false
    }
  }

  /** Verifies the PIN and applies progressive server-independent guessing delays. */
  fun verify(context: Context, pin: String): Boolean {
    val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val lockedUntil = prefs.getLong(KEY_LOCKED_UNTIL, 0L)
    val now = System.currentTimeMillis()
    if (now < lockedUntil) return false

    val saltText = prefs.getString(KEY_SALT, null) ?: return false
    val expectedText = prefs.getString(KEY_VERIFIER, null) ?: return false
    val valid = try {
      val salt = Base64.decode(saltText, Base64.NO_WRAP)
      val expected = Base64.decode(expectedText, Base64.NO_WRAP)
      val actual = hmac(salt, pin)
      MessageDigest.isEqual(expected, actual)
    } catch (_: Exception) {
      false
    }

    if (valid) {
      prefs.edit().putInt(KEY_FAILURES, 0).putLong(KEY_LOCKED_UNTIL, 0L).apply()
      unlockedForForeground = true
      return true
    }

    val failures = prefs.getInt(KEY_FAILURES, 0) + 1
    val delaySeconds = when {
      failures < 5 -> 0L
      failures < 8 -> 30L
      failures < 11 -> 120L
      failures < 14 -> 600L
      else -> 900L
    }
    prefs.edit()
      .putInt(KEY_FAILURES, failures)
      .putLong(KEY_LOCKED_UNTIL, now + delaySeconds * 1000L)
      .apply()
    return false
  }

  fun disable(context: Context, currentPin: String): Boolean {
    if (!verify(context, currentPin)) return false
    context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    deleteKeystoreKey()
    unlockedForForeground = true
    return true
  }

  fun remainingLockoutMillis(context: Context): Long {
    val until = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .getLong(KEY_LOCKED_UNTIL, 0L)
    return (until - System.currentTimeMillis()).coerceAtLeast(0L)
  }

  private fun hmac(salt: ByteArray, pin: String): ByteArray {
    val key = loadOrCreateKey()
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(key)
    mac.update(salt)
    return mac.doFinal(pin.toByteArray(Charsets.UTF_8))
  }

  private fun loadOrCreateKey(): SecretKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
    generator.init(
      KeyGenParameterSpec.Builder(
        KEYSTORE_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
      )
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
        .build()
    )
    return generator.generateKey()
  }

  private fun deleteKeystoreKey() {
    try {
      KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
        deleteEntry(KEYSTORE_ALIAS)
      }
    } catch (_: Exception) {
      // Clearing the preference record is still sufficient to disable the PIN gate.
    }
  }
}
