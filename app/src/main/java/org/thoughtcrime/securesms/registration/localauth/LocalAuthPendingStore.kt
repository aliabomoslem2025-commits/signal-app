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

  fun saveChallenge(challengeId: String, phoneNumber: String, nonce: String) {
    preferences.edit()
      .putString(challengeKey(challengeId, "phone"), phoneNumber)
      .putString(challengeKey(challengeId, "nonce"), nonce)
      .apply()
  }

  fun nonceForChallenge(challengeId: String): String? {
    return preferences.getString(challengeKey(challengeId, "nonce"), null)
  }

  fun phoneForChallenge(challengeId: String): String? {
    return preferences.getString(challengeKey(challengeId, "phone"), null)
  }

  fun clearChallenge(challengeId: String) {
    preferences.edit()
      .remove(challengeKey(challengeId, "phone"))
      .remove(challengeKey(challengeId, "nonce"))
      .apply()
  }

  fun saveRegistrationSession(sessionId: String, phoneNumber: String, code: String) {
    preferences.edit()
      .putString(sessionKey(sessionId, "phone"), phoneNumber)
      .putString(sessionKey(sessionId, "code"), code)
      .putBoolean(sessionKey(sessionId, "verified"), false)
      .apply()
  }

  fun phoneForSession(sessionId: String): String? {
    return preferences.getString(sessionKey(sessionId, "phone"), null)
  }

  fun consumeCode(sessionId: String): String? {
    val key = sessionKey(sessionId, "code")
    val code = preferences.getString(key, null)
    preferences.edit().remove(key).apply()
    return code
  }

  fun markVerified(sessionId: String) {
    preferences.edit().putBoolean(sessionKey(sessionId, "verified"), true).apply()
  }

  fun isVerified(sessionId: String): Boolean {
    return preferences.getBoolean(sessionKey(sessionId, "verified"), false)
  }

  fun clearSession(sessionId: String) {
    preferences.edit()
      .remove(sessionKey(sessionId, "phone"))
      .remove(sessionKey(sessionId, "code"))
      .remove(sessionKey(sessionId, "verified"))
      .apply()
  }

  private fun challengeKey(challengeId: String, field: String): String = "challenge:$challengeId:$field"
  private fun sessionKey(sessionId: String, field: String): String = "session:$sessionId:$field"
}
