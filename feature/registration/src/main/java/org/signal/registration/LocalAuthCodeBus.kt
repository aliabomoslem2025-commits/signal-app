package org.signal.registration

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull

/**
 * Delivers the server-issued, short-lived code to the existing 6-digit
 * verification screen without SMS/Google Play Services.
 */
object LocalAuthCodeBus {
  const val CHALLENGE_SESSION_PREFIX = "LOCAL1."
  data class Code(val sessionId: String, val value: String)

  private val state = MutableStateFlow<Code?>(null)
  val events = state.filterNotNull()

  @Synchronized
  fun publish(sessionId: String, code: String) {
    require(sessionId.startsWith(CHALLENGE_SESSION_PREFIX))
    require(code.length == 6 && code.all { it in '0'..'9' })
    state.value = Code(sessionId, code)
  }

  @Synchronized
  fun consume(sessionId: String, code: String) {
    if (state.value == Code(sessionId, code)) {
      state.value = null
    }
  }
}
