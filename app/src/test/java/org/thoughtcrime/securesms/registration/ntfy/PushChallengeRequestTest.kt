/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.thoughtcrime.securesms.registration.ntfy

import android.app.Application
import android.os.AsyncTask
import assertk.assertThat
import assertk.assertions.isGreaterThanOrEqualTo
import assertk.assertions.isLessThan
import assertk.assertions.isPresent
import io.mockk.called
import io.mockk.confirmVerified
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.thoughtcrime.securesms.isAbsent
import org.whispersystems.signalservice.api.SignalServiceAccountManager
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, application = Application::class)
class PushChallengeRequestTest {
  @Test
  fun pushChallengeBlocking_returns_absent_if_times_out() {
    val signal = mockk<SignalServiceAccountManager>(relaxUnitFun = true)
    val challenge = PushChallengeRequest.getPushChallengeBlocking(signal, "session ID", "signal-test-topic", 50L)
    assertThat(challenge).isAbsent()
  }

  @Test
  fun pushChallengeBlocking_waits_for_specified_period() {
    val signal = mockk<SignalServiceAccountManager>(relaxUnitFun = true)
    val startTime = System.currentTimeMillis()
    PushChallengeRequest.getPushChallengeBlocking(signal, "session ID", "signal-test-topic", 250L)
    val duration = System.currentTimeMillis() - startTime
    assertThat(duration).isGreaterThanOrEqualTo(250L)
  }

  @Test
  fun pushChallengeBlocking_completes_fast_if_posted_to_event_bus() {
    val signal = mockk<SignalServiceAccountManager> {
      every {
        requestRegistrationPushChallenge("session ID", "signal-test-topic")
      } answers {
        AsyncTask.execute { PushChallengeRequest.postChallengeResponse("CHALLENGE") }
      }
    }
    val startTime = System.currentTimeMillis()
    val challenge = PushChallengeRequest.getPushChallengeBlocking(signal, "session ID", "signal-test-topic", 500L)
    val duration = System.currentTimeMillis() - startTime
    assertThat(duration).isLessThan(500L)
    verify { signal.requestRegistrationPushChallenge("session ID", "signal-test-topic") }
    confirmVerified(signal)
    assertThat(challenge).isPresent().isEqualTo("CHALLENGE")
  }

  @Test
  fun pushChallengeBlocking_returns_without_request_if_topic_is_missing() {
    val signal = mockk<SignalServiceAccountManager>()
    val startTime = System.currentTimeMillis()
    val challenge = PushChallengeRequest.getPushChallengeBlocking(signal, "session ID", "", 500L)
    assertThat(System.currentTimeMillis() - startTime).isLessThan(500L)
    verify { signal wasNot called }
    assertThat(challenge).isAbsent()
  }

  @Test
  fun pushChallengeBlocking_returns_absent_if_request_throws() {
    val signal = mockk<SignalServiceAccountManager> {
      every { requestRegistrationPushChallenge(any(), any()) } throws IOException()
    }
    val challenge = PushChallengeRequest.getPushChallengeBlocking(signal, "session ID", "signal-test-topic", 500L)
    assertThat(challenge).isAbsent()
  }
}
