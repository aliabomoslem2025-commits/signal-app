package org.signal.registration

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow

/**
 * One-shot handoff from the app's LAN authentication controller to the verification-code screen.
 * A buffered channel keeps the response if navigation has not created the screen yet.
 */
object LocalAuthCodeBus {
  private val channel = Channel<String>(capacity = Channel.BUFFERED)

  val codes: Flow<String> = channel.receiveAsFlow()

  fun offer(code: String) {
    require(code.length == 6 && code.all(Char::isDigit)) { "Local verification code must contain six digits." }
    check(channel.trySend(code).isSuccess) { "A local verification code is already pending." }
  }
}