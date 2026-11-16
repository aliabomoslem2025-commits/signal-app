package org.thoughtcrime.securesms.push

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LanDestinationPolicyTest {
  private val policy = LanDestinationPolicy(listOf("https://signal.lan", "https://cdn.lan:8443"))

  @Test
  fun onlyConfiguredHttpsHostAndPort_areAllowed() {
    assertTrue(policy.permits("https", "signal.lan", 443))
    assertTrue(policy.permits("HTTPS", "CDN.LAN", 8443))
    assertFalse(policy.permits("http", "signal.lan", 80))
    assertFalse(policy.permits("https", "signal.org", 443))
    assertFalse(policy.permits("https", "cdn.lan", 443))
    assertFalse(policy.permits("https", "api.cdn.lan", 8443))
  }

  @Test
  fun userinfoAndNonHttpsConfiguration_areRejected() {
    assertThrows(IllegalArgumentException::class.java) {
      LanDestinationPolicy(listOf("https://user:secret@signal.lan"))
    }
    assertThrows(IllegalArgumentException::class.java) {
      LanDestinationPolicy(listOf("http://signal.lan"))
    }
  }
}
