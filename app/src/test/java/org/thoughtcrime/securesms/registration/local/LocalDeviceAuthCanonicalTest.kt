package org.thoughtcrime.securesms.registration.local

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Go local-auth accepts these exact newline-delimited, UTF-8 P-256 signed
 * messages. The tests intentionally use literal protocol fixtures rather
 * than regenerating expected strings from production implementation.
 */
class LocalDeviceAuthCanonicalTest {
  private val challengeId = "d6c2a9"
  private val phone = "+4915112345678"
  private val nonce = "AbcD23ef_-"
  private val code = "246801"

  @Test
  fun challenge_matchesServerWireFormat() {
    val expected = "signal-local-auth-v1\nd6c2a9\n+4915112345678\nAbcD23ef_-".toByteArray(Charsets.UTF_8)
    assertArrayEquals(expected, LocalDeviceAuthCanonical.challenge(challengeId, phone, nonce))
  }

  @Test
  fun completion_matchesServerWireFormat() {
    val expected = "signal-local-auth-complete-v1\nd6c2a9\n+4915112345678\nAbcD23ef_-\n246801".toByteArray(Charsets.UTF_8)
    assertArrayEquals(expected, LocalDeviceAuthCanonical.completion(challengeId, phone, nonce, code))
  }

  @Test
  fun signedCompletion_isBoundToPhoneNonceChallengeAndCode() {
    val expected = LocalDeviceAuthCanonical.completion(challengeId, phone, nonce, code)
    val variants = listOf(
      LocalDeviceAuthCanonical.completion("other-challenge", phone, nonce, code),
      LocalDeviceAuthCanonical.completion(challengeId, "+4915112345679", nonce, code),
      LocalDeviceAuthCanonical.completion(challengeId, phone, "other-nonce", code),
      LocalDeviceAuthCanonical.completion(challengeId, phone, nonce, "246802")
    )
    for (variant in variants) assertFalse(expected.contentEquals(variant))
  }

  @Test
  fun nonE164PhoneAndMalformedCode_areRejected() {
    assertThrows(IllegalArgumentException::class.java) {
      LocalDeviceAuthCanonical.challenge(challengeId, "4915112345678", nonce)
    }
    assertThrows(IllegalArgumentException::class.java) {
      LocalDeviceAuthCanonical.completion(challengeId, phone, nonce, "12345a")
    }
  }
}
