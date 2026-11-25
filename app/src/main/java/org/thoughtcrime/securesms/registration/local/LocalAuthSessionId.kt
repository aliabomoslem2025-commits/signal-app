/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.registration.local

import android.util.Base64
import org.json.JSONObject
import org.signal.registration.LocalAuthCodeBus
import java.nio.charset.StandardCharsets
import java.time.Instant

/**
 * Strict, client-side validation for the opaque local-auth session IDs persisted by registration.
 *
 * This deliberately does not verify the HMAC. Only the Local Auth sidecar can verify the ticket
 * signature and database state (expiry, device binding, revocation and one-time use). The client
 * checks the envelope and its expiry so it can discard stale saved flows before submitting them.
 */
internal object LocalAuthSessionId {
  private const val COMPLETED_PREFIX = "LAN1."
  private const val MAX_SESSION_ID_LENGTH = 8192
  private const val MAX_TICKET_LENGTH = 4096
  private const val MAX_ENVELOPE_BYTES = MAX_TICKET_LENGTH + COMPLETED_PREFIX.length
  private const val MAX_CHALLENGE_STATE_BYTES = 2048
  private const val MAX_TICKET_CLAIMS_BYTES = 2048
  private const val SIGNATURE_BYTES = 32
  private const val NONCE_BYTES = 32

  private val rawUrlBase64Pattern = Regex("^[A-Za-z0-9_-]+$")
  private val e164Pattern = Regex("^\\+[1-9][0-9]{7,14}$")
  private val hex48Pattern = Regex("^[0-9a-f]{48}$")
  private val hex64Pattern = Regex("^[0-9a-f]{64}$")

  fun isChallengeSession(
    id: String,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000
  ): Boolean = decodeChallenge(id, nowEpochSeconds) != null

  /**
   * Decodes only a well-formed, unexpired challenge. Older persisted challenge IDs without an
   * expiry are intentionally rejected and restarted rather than sent to the sidecar.
   */
  fun decodeChallenge(
    id: String,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000
  ): JSONObject? {
    if (!id.startsWith(LocalAuthCodeBus.CHALLENGE_SESSION_PREFIX) || id.length > MAX_SESSION_ID_LENGTH) {
      return null
    }

    val encodedState = id.removePrefix(LocalAuthCodeBus.CHALLENGE_SESSION_PREFIX)
    val stateBytes = decodeRawUrlBase64(encodedState, MAX_CHALLENGE_STATE_BYTES) ?: return null

    return try {
      val state = JSONObject(String(stateBytes, StandardCharsets.UTF_8))
      val challengeId = state.optString("challengeId")
      val nonce = state.optString("nonce")
      val phone = state.optString("phone")
      val expiresAt = Instant.parse(state.optString("expiresAt")).epochSecond
      val nonceBytes = decodeRawUrlBase64(nonce, NONCE_BYTES)

      if (
        !hex48Pattern.matches(challengeId) ||
        !e164Pattern.matches(phone) ||
        nonceBytes?.size != NONCE_BYTES ||
        expiresAt <= nowEpochSeconds
      ) {
        null
      } else {
        state
      }
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Checks the wrapped ticket format and exp claim before restoring a completed session.
   * The server still performs the real signature and single-use validation during registration.
   */
  fun isCompletedSession(
    id: String,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000
  ): Boolean {
    if (id.isEmpty() || id.length > MAX_SESSION_ID_LENGTH) {
      return false
    }

    return try {
      // The server's sessionId is the raw Base64URL encoding of "LAN1." + ticket.
      // Unlike challenge IDs, the completed session ID itself has no textual prefix.
      val envelopeBytes = decodeRawUrlBase64(id, MAX_ENVELOPE_BYTES) ?: return false
      val envelope = String(envelopeBytes, StandardCharsets.UTF_8)
      if (!envelope.startsWith(COMPLETED_PREFIX)) return false

      val ticket = envelope.removePrefix(COMPLETED_PREFIX)
      if (ticket.isEmpty() || ticket.length > MAX_TICKET_LENGTH) return false

      val parts = ticket.split('.')
      if (parts.size != 3 || parts[0] != "lan1") return false

      val claimsBytes = decodeRawUrlBase64(parts[1], MAX_TICKET_CLAIMS_BYTES) ?: return false
      val signatureBytes = decodeRawUrlBase64(parts[2], SIGNATURE_BYTES) ?: return false
      if (signatureBytes.size != SIGNATURE_BYTES) return false

      val claims = JSONObject(String(claimsBytes, StandardCharsets.UTF_8))
      val phone = claims.optString("phone")
      val androidIdHash = claims.optString("androidIdHash")
      val jti = claims.optString("jti")
      val expiryValue = claims.opt("exp") as? Number ?: return false
      val expiresAt = expiryValue.toLong()

      e164Pattern.matches(phone) &&
        hex64Pattern.matches(androidIdHash) &&
        hex48Pattern.matches(jti) &&
        expiryValue.toDouble() == expiresAt.toDouble() &&
        expiresAt > nowEpochSeconds
    } catch (_: Exception) {
      false
    }
  }

  private fun decodeRawUrlBase64(value: String, maxDecodedBytes: Int): ByteArray? {
    if (value.isEmpty() || !rawUrlBase64Pattern.matches(value)) return null

    val maxEncodedLength = ((maxDecodedBytes + 2) / 3) * 4
    if (value.length > maxEncodedLength) return null

    return try {
      Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        .takeIf { it.isNotEmpty() && it.size <= maxDecodedBytes }
    } catch (_: Exception) {
      null
    }
  }
}
