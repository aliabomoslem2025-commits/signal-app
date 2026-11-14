package org.thoughtcrime.securesms.network.local

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.math.min

/**
 * Local app-unlock PIN. Only a salted PBKDF2 verifier is stored; the PIN is never sent to a server.
 * The unlock flag is process-memory only and is reset whenever the app enters background.
 */
object LocalAppPinManager {
  private const val PREFS = "local_app_pin"
  private const val SALT = "salt"
  private const val HASH = "hash"
  private const val ATTEMPTS = "attempts"
  private const val LOCK_UNTIL = "lock_until"
  private const val ITERATIONS = 180_000
  private const val KEY_BITS = 256
  private const val MAX_LOCK_MILLIS = 15 * 60 * 1000L

  @Volatile private var unlocked = false
  @Volatile private var promptStarted = false

  fun isEnabled(context: Context): Boolean {
    val prefs = prefs(context)
    return !prefs.getString(SALT, null).isNullOrBlank() && !prefs.getString(HASH, null).isNullOrBlank()
  }

  fun setPin(context: Context, pin: String) {
    require(pin.matches(Regex("^[0-9]{6,12}$"))) { "PIN باید بین ۶ تا ۱۲ رقم باشد." }
    val salt = ByteArray(16).also(SecureRandom()::nextBytes)
    val hash = derive(pin, salt)
    prefs(context).edit()
      .putString(SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
      .putString(HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
      .putInt(ATTEMPTS, 0)
      .putLong(LOCK_UNTIL, 0L)
      .apply()
    unlocked = true
    promptStarted = false
  }

  fun disable(context: Context, currentPin: String) {
    require(verify(context, currentPin)) { "PIN فعلی صحیح نیست." }
    prefs(context).edit().clear().apply()
    unlocked = true
    promptStarted = false
  }

  fun verify(context: Context, pin: String): Boolean {
    val prefs = prefs(context)
    if (remainingLockMillis(context) > 0) return false
    val salt = decode(prefs.getString(SALT, null)) ?: return false
    val expected = decode(prefs.getString(HASH, null)) ?: return false
    val actual = derive(pin, salt)
    val valid = MessageDigest.isEqual(expected, actual)
    if (valid) {
      prefs.edit().putInt(ATTEMPTS, 0).putLong(LOCK_UNTIL, 0L).apply()
      onUnlocked()
      return true
    }

    val attempts = prefs.getInt(ATTEMPTS, 0) + 1
    val lockMillis = if (attempts < 5) 0L else min(MAX_LOCK_MILLIS, 1_000L shl min(10, attempts - 5))
    prefs.edit().putInt(ATTEMPTS, attempts)
      .putLong(LOCK_UNTIL, if (lockMillis == 0L) 0L else System.currentTimeMillis() + lockMillis)
      .apply()
    return false
  }

  fun remainingLockMillis(context: Context): Long {
    val until = prefs(context).getLong(LOCK_UNTIL, 0L)
    return (until - System.currentTimeMillis()).coerceAtLeast(0L)
  }

  fun shouldPrompt(context: Context): Boolean {
    if (!isEnabled(context) || unlocked || promptStarted) return false
    promptStarted = true
    return true
  }

  fun onUnlocked() {
    unlocked = true
    promptStarted = false
  }

  fun onBackground() {
    if (isProcessPinEnabled) {
      unlocked = false
      promptStarted = false
    }
  }

  @Volatile private var isProcessPinEnabled: Boolean = false

  private fun prefs(context: Context) =
    context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  private fun decode(value: String?): ByteArray? {
    if (value.isNullOrBlank()) return null
    return runCatching { Base64.decode(value, Base64.NO_WRAP) }.getOrNull()
  }

  private fun derive(pin: String, salt: ByteArray): ByteArray {
    val spec = PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, KEY_BITS)
    return try {
      SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    } finally {
      spec.clearPassword()
    }
  }
}