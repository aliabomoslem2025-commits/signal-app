package org.thoughtcrime.securesms.registration.local

import android.content.Context
import android.content.Intent
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * App-local PIN lock. This PIN is independent from Signal's account/SVR PIN and is never sent to any server.
 *
 * The stored value is a PBKDF2-HMAC-SHA256 verifier with a random salt. The app requires the PIN again after it
 * returns from the background or after process recreation.
 */
object LocalPinLockManager {
  private const val PREFS = "local_app_pin_lock"
  private const val SALT_KEY = "pin_salt"
  private const val HASH_KEY = "pin_hash"
  private const val ITERATIONS = 350_000
  private const val KEY_BITS = 256
  private const val MAX_ATTEMPTS = 5
  private const val LOCKOUT_MS = 30_000L

  @Volatile
  private var locked = true

  @Volatile
  private var unlockActivityVisible = false

  @Volatile
  private var failedAttempts = 0

  @Volatile
  private var lockoutUntil = 0L

  @JvmStatic
  fun isEnabled(context: Context): Boolean {
    val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    return prefs.contains(SALT_KEY) && prefs.contains(HASH_KEY)
  }

  fun setPin(context: Context, pin: String) {
    require(pin.matches(Regex("[0-9]{6,12}"))) { "PIN must contain 6 to 12 digits" }
    val salt = ByteArray(16).also(SecureRandom()::nextBytes)
    val hash = derive(pin, salt)
    context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .edit()
      .putString(SALT_KEY, Base64.encodeToString(salt, Base64.NO_WRAP))
      .putString(HASH_KEY, Base64.encodeToString(hash, Base64.NO_WRAP))
      .apply()
    failedAttempts = 0
    lockoutUntil = 0L
    locked = false
    unlockActivityVisible = false
  }

  fun removePin(context: Context) {
    context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .edit()
      .remove(SALT_KEY)
      .remove(HASH_KEY)
      .apply()
    failedAttempts = 0
    lockoutUntil = 0L
    locked = false
    unlockActivityVisible = false
  }

  fun verifyPin(context: Context, pin: String): Boolean {
    if (!isEnabled(context) || System.currentTimeMillis() < lockoutUntil) return false
    val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val salt = Base64.decode(prefs.getString(SALT_KEY, null) ?: return false, Base64.NO_WRAP)
    val expected = Base64.decode(prefs.getString(HASH_KEY, null) ?: return false, Base64.NO_WRAP)
    val actual = derive(pin, salt)
    val valid = MessageDigest.isEqual(expected, actual)
    if (valid) {
      failedAttempts = 0
      lockoutUntil = 0L
      locked = false
      unlockActivityVisible = false
    } else {
      failedAttempts += 1
      if (failedAttempts >= MAX_ATTEMPTS) {
        failedAttempts = 0
        lockoutUntil = System.currentTimeMillis() + LOCKOUT_MS
      }
    }
    return valid
  }

  fun lockoutRemainingMs(): Long = (lockoutUntil - System.currentTimeMillis()).coerceAtLeast(0L)

  @JvmStatic
  fun onAppBackgrounded(context: Context) {
    if (isEnabled(context)) {
      locked = true
      unlockActivityVisible = false
    }
  }

  @JvmStatic
  fun onAppForegrounded(context: Context) {
    if (!isEnabled(context) || !locked || unlockActivityVisible) return
    unlockActivityVisible = true
    val intent = Intent(context, LocalPinUnlockActivity::class.java)
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    context.startActivity(intent)
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
