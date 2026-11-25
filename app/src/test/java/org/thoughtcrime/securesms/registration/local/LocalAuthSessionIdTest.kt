/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.registration.local

import android.app.Application
import android.util.Base64
import assertk.assertThat
import assertk.assertions.isFalse
import assertk.assertions.isNotNull
import assertk.assertions.isTrue
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.signal.registration.LocalAuthCodeBus
import java.nio.charset.StandardCharsets
import java.time.Instant

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, manifest = Config.NONE)
class LocalAuthSessionIdTest {

  private val now = 1_800_000_000L

  @Test
  fun `accepts a well formed completed session before expiry`() {
    val sessionId = completedSessionId(expiresAt = now + 60)

    assertThat(LocalAuthSessionId.isCompletedSession(sessionId, now)).isTrue()
  }

  @Test
  fun `rejects a completed session at its exact expiry boundary`() {
    val sessionId = completedSessionId(expiresAt = now)

    assertThat(LocalAuthSessionId.isCompletedSession(sessionId, now)).isFalse()
  }

  @Test
  fun `rejects an expired completed session`() {
    val sessionId = completedSessionId(expiresAt = now - 1)

    assertThat(LocalAuthSessionId.isCompletedSession(sessionId, now)).isFalse()
  }

  @Test
  fun `rejects malformed completed session envelopes`() {
    assertThat(LocalAuthSessionId.isCompletedSession("LAN1.not-valid!!", now)).isFalse()
    assertThat(LocalAuthSessionId.isCompletedSession(encodeUrlBase64("not-a-ticket".toByteArray()), now)).isFalse()
  }

  @Test
  fun `rejects malformed ticket signatures`() {
    val sessionId = completedSessionId(expiresAt = now + 60, signatureBytes = 31)

    assertThat(LocalAuthSessionId.isCompletedSession(sessionId, now)).isFalse()
  }

  @Test
  fun `rejects tickets with missing or invalid identity claims`() {
    val missingExpiry = completedSessionId(expiresAt = null)
    val invalidDeviceHash = completedSessionId(expiresAt = now + 60, androidIdHash = "not-a-hash")

    assertThat(LocalAuthSessionId.isCompletedSession(missingExpiry, now)).isFalse()
    assertThat(LocalAuthSessionId.isCompletedSession(invalidDeviceHash, now)).isFalse()
  }

  @Test
  fun `accepts a well formed challenge before expiry`() {
    val sessionId = challengeSessionId(expiresAt = now + 60)

    assertThat(LocalAuthSessionId.isChallengeSession(sessionId, now)).isTrue()
    assertThat(LocalAuthSessionId.decodeChallenge(sessionId, now)).isNotNull()
  }

  @Test
  fun `rejects an expired challenge`() {
    val sessionId = challengeSessionId(expiresAt = now)

    assertThat(LocalAuthSessionId.isChallengeSession(sessionId, now)).isFalse()
    assertThat(LocalAuthSessionId.decodeChallenge(sessionId, now) == null).isTrue()
  }

  @Test
  fun `rejects legacy challenges without an expiry`() {
    val sessionId = challengeSessionId(expiresAt = null)

    assertThat(LocalAuthSessionId.isChallengeSession(sessionId, now)).isFalse()
  }

  @Test
  fun `rejects challenges with malformed nonce or phone number`() {
    val invalidNonce = challengeSessionId(expiresAt = now + 60, nonceBytes = 31)
    val invalidPhone = challengeSessionId(expiresAt = now + 60, phone = "not-a-phone")

    assertThat(LocalAuthSessionId.isChallengeSession(invalidNonce, now)).isFalse()
    assertThat(LocalAuthSessionId.isChallengeSession(invalidPhone, now)).isFalse()
  }

  private fun completedSessionId(
    expiresAt: Long?,
    androidIdHash: String = "a".repeat(64),
    signatureBytes: Int = 32
  ): String {
    val claims = JSONObject()
      .put("phone", "+15551234567")
      .put("androidIdHash", androidIdHash)
      .put("jti", "b".repeat(48))

    if (expiresAt != null) {
      claims.put("exp", expiresAt)
    }

    val payload = encodeUrlBase64(claims.toString().toByteArray(StandardCharsets.UTF_8))
    val signature = encodeUrlBase64(ByteArray(signatureBytes) { 0x5a.toByte() })
    val ticket = "lan1.$payload.$signature"
    val envelope = "LAN1.$ticket"
    return encodeUrlBase64(envelope.toByteArray(StandardCharsets.UTF_8))
  }

  private fun challengeSessionId(
    expiresAt: Long?,
    nonceBytes: Int = 32,
    phone: String = "+15551234567"
  ): String {
    val state = JSONObject()
      .put("challengeId", "c".repeat(48))
      .put("nonce", encodeUrlBase64(ByteArray(nonceBytes) { 0x3a.toByte() }))
      .put("phone", phone)

    if (expiresAt != null) {
      state.put("expiresAt", Instant.ofEpochSecond(expiresAt).toString())
    }

    return LocalAuthCodeBus.CHALLENGE_SESSION_PREFIX +
      encodeUrlBase64(state.toString().toByteArray(StandardCharsets.UTF_8))
  }

  private fun encodeUrlBase64(bytes: ByteArray): String {
    return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
  }
}
