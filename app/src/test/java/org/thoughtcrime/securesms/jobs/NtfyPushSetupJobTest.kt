package org.thoughtcrime.securesms.jobs

import android.app.Application
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Rule
import org.junit.Test
import org.thoughtcrime.securesms.testutil.MockSignalStoreRule

class NtfyPushSetupJobTest {
  @get:Rule
  val signalStore = MockSignalStoreRule()

  @Test
  fun clearsLegacyFcmStateForUnregisteredAccount() {
    every { signalStore.account.isRegistered } returns false

    NtfyPushSetupJob().apply {
      setContext(mockk<Application>(relaxed = true))
    }.onRun()

    verify { signalStore.account.fcmEnabled = false }
    verify { signalStore.account.fcmToken = null }
  }
}
