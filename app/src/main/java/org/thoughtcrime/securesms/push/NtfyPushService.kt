package org.thoughtcrime.securesms.push

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.signal.core.util.SafeForegroundService
import org.signal.core.util.logging.Log
import org.signal.libsignal.net.RequestResult
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.jobs.MessageFetchJob
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.registration.local.LocalServerConfig
import java.io.IOException
import java.net.Proxy
import java.net.URL
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.math.min

/**
 * Embedded ntfy wake-up subscriber. Fetches the actual encrypted messages
 * from Signal's authenticated receive channel; never transports envelopes
 * or plaintext through ntfy. No separate ntfy Android app or Firebase needed.
 */
class NtfyPushService : SafeForegroundService() {
  companion object {
    private val TAG = Log.tag(NtfyPushService::class.java)
    private const val CHANNEL_ID = "lan_ntfy_listener"
    private const val FOREGROUND_ID = 25341
    private const val MAX_BACKOFF_SECONDS = 60L

    @JvmStatic
    fun start(context: android.content.Context): Boolean = SafeForegroundService.start(context, NtfyPushService::class.java)

    @JvmStatic
    fun stop(context: android.content.Context): Boolean = SafeForegroundService.stop(context, NtfyPushService::class.java)
  }

  override val tag: String get() = TAG
  override val notificationId: Int get() = FOREGROUND_ID

  private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
  private var running: Job? = null

  @Volatile private var connection: HttpsURLConnection? = null

  override fun serviceType(intent: Intent): Int = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING else 0

  override fun getForegroundNotification(intent: Intent): Notification {
    val manager = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= 26) {
      manager.createNotificationChannel(
        NotificationChannel(CHANNEL_ID, "Signal LAN messages", NotificationManager.IMPORTANCE_MIN)
      )
    }
    return NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(R.drawable.ic_notification)
      .setContentTitle("Signal LAN")
      .setContentText("Secure message notifications are enabled")
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setOngoing(true)
      .setSilent(true)
      .build()
  }

  override fun onServiceStartCommandReceived(intent: Intent) {
    if (running?.isActive == true) return
    running = scope.launch {
      subscribeLoop()
    }
  }

  override fun onServiceStopCommandReceived(intent: Intent) {
    running?.cancel()
    connection?.disconnect()
    running = null
  }

  override fun onDestroy() {
    connection?.disconnect()
    scope.cancel()
    super.onDestroy()
  }

  private suspend fun subscribeLoop() {
    var backoff = 2L
    var lastMessageId: String? = null
    var previousTopic: String? = null
    while (currentCoroutineContext().isActive) {
      try {
        if (!SignalStore.account.isRegistered) {
          delay(5_000)
          continue
        }
        val result = AppDependencies.accountApiV2.registerNtfyTopic()
        if (result !is RequestResult.Success) {
          throw IOException("Could not provision private ntfy topic")
        }
        currentCoroutineContext().ensureActive()
        val topic = result.result
        require(topic.matches(Regex("signal-[A-Za-z0-9_-]{32,64}"))) { "Invalid LAN notification topic" }
        if (previousTopic != topic) {
          lastMessageId = null
          previousTopic = topic
        }
        consumeStream(topic, lastMessageId) { eventId ->
          lastMessageId = eventId
          backoff = 2L
        }
      } catch (cancelled: CancellationException) {
        throw cancelled
      } catch (e: Exception) {
        // Do not log the private ntfy topic, URL with topic, or any auth token.
        Log.w(TAG, "Local ntfy stream interrupted; reconnecting")
      }
      if (!currentCoroutineContext().isActive) break
      delay(backoff * 1000)
      backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
    }
  }

  private fun configureTrust(conn: HttpsURLConnection) {
    val trustStore = LocalServerTrustStore(this)
    val store = KeyStore.getInstance("PKCS12")
    trustStore.keyStoreInputStream.use { store.load(it, trustStore.keyStorePassword.toCharArray()) }
    val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
    conn.sslSocketFactory = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }.socketFactory
    // The default platform hostname verifier remains unchanged.
  }

  private suspend fun consumeStream(topic: String, resumeFrom: String?, onEvent: (String) -> Unit) {
    val context = currentCoroutineContext()
    context.ensureActive()
    // The per-device topic is a high-entropy capability assigned only after
    // authenticated registration. It is not embedded in the APK or logs.
    val base = LocalServerConfig.load(this).ntfyBaseUrl
    val since = resumeFrom?.let { "?since=" + java.net.URLEncoder.encode(it, "UTF-8") } ?: "?since=all"
    val url = URL("$base/$topic/sse$since")
    val conn = (url.openConnection(Proxy.NO_PROXY) as HttpsURLConnection).apply {
      instanceFollowRedirects = false
      configureTrust(this)
      requestMethod = "GET"
      connectTimeout = 10_000
      readTimeout = 60_000
      setRequestProperty("Accept", "text/event-stream")
      setRequestProperty("Cache-Control", "no-cache")
      setRequestProperty("X-Firebase", "no")
      useCaches = false
    }
    connection = conn
    var last = resumeFrom
    try {
      context.ensureActive()
      if (conn.responseCode != 200) throw IOException("ntfy subscription failed (HTTP ${conn.responseCode})")
      conn.inputStream.bufferedReader().use { reader ->
        while (context.isActive) {
          val line = reader.readLine() ?: break
          context.ensureActive()
          if (!line.startsWith("data:")) continue
          val body = line.removePrefix("data:").trim()
          val event = try { JSONObject(body) } catch (_: Exception) { continue }
          if (event.optString("event") != "message") continue
          val eventId = event.optString("id")
          if (eventId.isNotBlank() && eventId == last) continue
          when (event.optString("message")) {
            "wake" -> AppDependencies.jobManager.add(MessageFetchJob())
            else -> {
              // No message contents, credentials or link previews are read
              // from ntfy. Other control events are intentionally ignored.
            }
          }
          if (eventId.isNotBlank()) {
            last = eventId
            onEvent(eventId)
          }
        }
      }
    } finally {
      conn.disconnect()
      if (connection === conn) connection = null
    }
  }
}
