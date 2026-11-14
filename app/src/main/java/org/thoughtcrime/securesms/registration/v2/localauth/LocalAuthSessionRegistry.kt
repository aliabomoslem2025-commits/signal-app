package org.thoughtcrime.securesms.registration.v2.localauth

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory, short-lived registration handoff. Verification codes are never persisted or logged.
 */
object LocalAuthSessionRegistry {
  data class Pending(
    val phone: String,
    val code: String,
    val createdAtMillis: Long = System.currentTimeMillis()
  )

  private val pending = ConcurrentHashMap<String, Pending>()

  fun put(challengeId: String, phone: String, code: String) {
    require(challengeId.isNotBlank() && code.length == 6)
    purgeExpired()
    pending[challengeId] = Pending(phone, code)
  }

  fun get(challengeId: String): Pending? {
    purgeExpired()
    return pending[challengeId]
  }

  fun remove(challengeId: String) {
    pending.remove(challengeId)
  }

  fun isLocalRegistrationSession(sessionId: String): Boolean {
    return try {
      val decoded = Base64.decode(sessionId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      String(decoded, StandardCharsets.UTF_8).startsWith("LAN1.")
    } catch (_: IllegalArgumentException) {
      false
    }
  }

  private fun purgeExpired() {
    val cutoff = System.currentTimeMillis() - SESSION_TTL_MILLIS
    pending.entries.removeIf { it.value.createdAtMillis < cutoff }
  }

  private const val SESSION_TTL_MILLIS = 5 * 60 * 1000L
}