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
 * Only a salted PBKDF2-HMAC-SHA256 verifier is stored. Failed attempts and lockout deadlines are persisted so
 * restarting the process cannot reset the local brute-force delay.
 */
object LocalPinLockManager {
  private const val PREFS = "local_app_pin_lock"
  private const val SALT_KEY = "pin_salt"
  private const val HASH_KEY = "pin_hash"
  private const val FAILED_ATTEMPTS_KEY = "failed_attempts"
  private const val LOCKOUT_UNTIL_KEY = "lockout_until"
  private const val ITERATIONS = 350_000
  private const val KEY_BITS = 256
  private const val MAX_ATTEMPTS = 5
  private const val LOCKOUT_MS = 30_000L

  @Volatile
  private var locked = true

  @Volatile
  private var unlockActivityVisible = false

  @JvmStatic
  fun isEnabled(context: Context): Boolean {
    val prefs = preferences(context)
    return prefs.contains(SALT_KEY) && prefs.contains(HASH_KEY)
  }

  /** First-time setup. Replacing an existing PIN requires the current PIN via [changePin]. */
  fun setPin(context: Context, pin: String) {
    require(!isEnabled(context)) { "A PIN is already enabled; verify the current PIN before changing it." }
    saveNewPin(context, pin)
  }

  fun changePin(context: Context, currentPin: String, newPin: String): Boolean {
    validatePin(newPin)
    if (!verifyPin(context, currentPin)) return false
    saveNewPin(context, newPin)
    return true
  }

  fun removePin(context: Context, currentPin: String): Boolean {
    if (!verifyPin(context, currentPin)) return false
    preferences(context).edit()
      .remove(SALT_KEY)
      .remove(HASH_KEY)
      .remove(FAILED_ATTEMPTS_KEY)
      .remove(LOCKOUT_UNTIL_KEY)
      .commit()
    locked = false
    unlockActivityVisible = false
    return true
  }

  fun verifyPin(context: Context, pin: String): Boolean {
    val prefs = preferences(context)
    if (!isEnabled(context) || lockoutRemainingMs(context) > 0L) return false

    val salt = Base64.decode(prefs.getString(SALT_KEY, null) ?: return false, Base64.NO_WRAP)
    val expected = Base64.decode(prefs.getString(HASH_KEY, null) ?: return false, Base64.NO_WRAP)
    val actual = derive(pin, salt)
    val valid = MessageDigest.isEqual(expected, actual)

    if (valid) {
      prefs.edit()
        .putInt(FAILED_ATTEMPTS_KEY, 0)
        .putLong(LOCKOUT_UNTIL_KEY, 0L)
        .commit()
      locked = false
      unlockActivityVisible = false
    } else {
      val attempts = prefs.getInt(FAILED_ATTEMPTS_KEY, 0) + 1
      val lockoutUntil = if (attempts >= MAX_ATTEMPTS) System.currentTimeMillis() + LOCKOUT_MS else 0L
      prefs.edit()
        .putInt(FAILED_ATTEMPTS_KEY, if (lockoutUntil > 0L) 0 else attempts)
        .putLong(LOCKOUT_UNTIL_KEY, lockoutUntil)
        .commit()
    }
    return valid
  }

  fun lockoutRemainingMs(context: Context): Long {
    val until = preferences(context).getLong(LOCKOUT_UNTIL_KEY, 0L)
    return (until - System.currentTimeMillis()).coerceAtLeast(0L)
  }

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

  private fun saveNewPin(context: Context, pin: String) {
    validatePin(pin)
    val salt = ByteArray(16).also(SecureRandom()::nextBytes)
    val hash = derive(pin, salt)
    preferences(context).edit()
      .putString(SALT_KEY, Base64.encodeToString(salt, Base64.NO_WRAP))
      .putString(HASH_KEY, Base64.encodeToString(hash, Base64.NO_WRAP))
      .putInt(FAILED_ATTEMPTS_KEY, 0)
      .putLong(LOCKOUT_UNTIL_KEY, 0L)
      .commit()
    locked = false
    unlockActivityVisible = false
  }

  private fun validatePin(pin: String) {
    require(pin.matches(Regex("[0-9]{6,12}"))) { "PIN must contain 6 to 12 digits" }
  }

  private fun preferences(context: Context) =
    context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  private fun derive(pin: String, salt: ByteArray): ByteArray {
    val spec = PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, KEY_BITS)
    return try {
      SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    } finally {
      spec.clearPassword()
    }
  }
}
