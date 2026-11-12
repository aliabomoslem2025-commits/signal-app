package org.signal.registration

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow

/**
 * One-shot in-process handoff for verification codes delivered by the private LAN authentication API.
 * This is deliberately not persisted and is consumed by the active registration screen only.
 */
object LocalAuthCodeBus {
  data class Code(val challengeSessionId: String, val value: String)

  private val channel = Channel<Code>(capacity = Channel.BUFFERED)
  val codes = channel.receiveAsFlow()

  suspend fun publish(challengeSessionId: String, code: String) {
    channel.send(Code(challengeSessionId, code))
  }
}
