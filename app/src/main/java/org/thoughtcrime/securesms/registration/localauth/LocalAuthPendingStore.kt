/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.thoughtcrime.securesms.registration.localauth

import android.content.Context

/**
 * Short-lived registration-flow state for the LAN challenge. This contains no private key material.
 * The server remains authoritative for challenge expiry and code verification.
 */
class LocalAuthPendingStore(context: Context) {
  private val preferences = context.applicationContext.getSharedPreferences("local_device_auth_pending", Context.MODE_PRIVATE)

  companion object {
    private const val CHALLENGE_TTL_MILLIS = 180_000L
    private const val SESSION_TTL_MILLIS = 900_000L
  }

  fun saveChallenge(challengeId: String, phoneNumber: String, nonce: String) {
    preferences.edit()
      .putString(challengeKey(challengeId, "phone"), phoneNumber)
      .putString(challengeKey(challengeId, "nonce"), nonce)
      .putLong(challengeKey(challengeId, "expires"), System.currentTimeMillis() + CHALLENGE_TTL_MILLIS)
      .apply()
  }

  fun nonceForChallenge(challengeId: String): String? {
    if (!isChallengeValid(challengeId)) return null
    return preferences.getString(challengeKey(challengeId, "nonce"), null)
  }

  fun phoneForChallenge(challengeId: String): String? {
    if (!isChallengeValid(challengeId)) return null
    return preferences.getString(challengeKey(challengeId, "phone"), null)
  }

  fun clearChallenge(challengeId: String) {
    preferences.edit()
      .remove(challengeKey(challengeId, "phone"))
      .remove(challengeKey(challengeId, "nonce"))
      .remove(challengeKey(challengeId, "expires"))
      .apply()
  }

  fun saveRegistrationSession(sessionId: String, phoneNumber: String, code: String) {
    preferences.edit()
      .putString(sessionKey(sessionId, "phone"), phoneNumber)
      .putString(sessionKey(sessionId, "code"), code)
      .putBoolean(sessionKey(sessionId, "verified"), false)
      .putLong(sessionKey(sessionId, "expires"), System.currentTimeMillis() + SESSION_TTL_MILLIS)
      .apply()
  }

  fun phoneForSession(sessionId: String): String? {
    if (!isSessionValid(sessionId)) return null
    return preferences.getString(sessionKey(sessionId, "phone"), null)
  }

  fun consumeCode(sessionId: String): String? {
    if (!isSessionValid(sessionId)) return null
    val key = sessionKey(sessionId, "code")
    val code = preferences.getString(key, null)
    preferences.edit().remove(key).apply()
    return code
  }

  fun markVerified(sessionId: String) {
    if (isSessionValid(sessionId)) {
      preferences.edit().putBoolean(sessionKey(sessionId, "verified"), true).apply()
    }
  }

  fun isVerified(sessionId: String): Boolean {
    return isSessionValid(sessionId) && preferences.getBoolean(sessionKey(sessionId, "verified"), false)
  }

  fun clearSession(sessionId: String) {
    preferences.edit()
      .remove(sessionKey(sessionId, "phone"))
      .remove(sessionKey(sessionId, "code"))
      .remove(sessionKey(sessionId, "verified"))
      .remove(sessionKey(sessionId, "expires"))
      .apply()
  }

  private fun isChallengeValid(challengeId: String): Boolean {
    val expiresAt = preferences.getLong(challengeKey(challengeId, "expires"), 0L)
    if (expiresAt > System.currentTimeMillis()) return true
    clearChallenge(challengeId)
    return false
  }

  private fun isSessionValid(sessionId: String): Boolean {
    val expiresAt = preferences.getLong(sessionKey(sessionId, "expires"), 0L)
    if (expiresAt > System.currentTimeMillis()) return true
    clearSession(sessionId)
    return false
  }

  private fun challengeKey(challengeId: String, field: String): String = "challenge:$challengeId:$field"
  private fun sessionKey(sessionId: String, field: String): String = "session:$sessionId:$field"
}
