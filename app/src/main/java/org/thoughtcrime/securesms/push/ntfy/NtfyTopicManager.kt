package org.thoughtcrime.securesms.push.ntfy

import android.content.Context
import org.signal.core.util.Base64
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.network.local.LocalServerConfigStore
import java.security.SecureRandom

/**
 * Creates an opaque per-device ntfy topic. The topic is a bearer-like routing capability and
 * must never be derived from an account identifier, phone number or Android ID.
 */
object NtfyTopicManager {
  private val secureRandom = SecureRandom()

  @Synchronized
  fun getOrCreate(context: Context): String {
    val existing = SignalStore.account.ntfyTopic
    if (!existing.isNullOrBlank()) {
      NtfySubscriptionService.start(context)
      return existing
    }

    val config = LocalServerConfigStore.load(context)
    require(config.ntfyReaderToken.isNotBlank()) {
      "ابتدا نشانی ntfy و توکن خواندن آن را در تنظیمات شبکه محلی وارد کنید."
    }

    val random = ByteArray(32)
    secureRandom.nextBytes(random)
    val topic = "signal-" + Base64.encodeUrlSafeWithoutPadding(random)
    SignalStore.account.ntfyTopic = topic
    SignalStore.account.ntfyEnabled = true
    NtfySubscriptionService.start(context)
    return topic
  }
}
