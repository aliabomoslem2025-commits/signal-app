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
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
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
    private const val CURSOR_PREFS = "lan_ntfy_resume"
    private const val CURSOR_TOPIC_HASH = "topic_fingerprint"
    private const val CURSOR_MESSAGE_ID = "last_message_id"

    @JvmStatic
    fun start(context: android.content.Context): Boolean =
      SafeForegroundService.start(context, NtfyPushService::class.java)

    @JvmStatic
    fun stop(context: android.content.Context): Boolean =
      SafeForegroundService.stop(context, NtfyPushService::class.java)
  }

  override val tag: String get() = TAG
  override val notificationId: Int get() = FOREGROUND_ID

  private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
  private var running: Job? = null
  @Volatile private var connection: HttpsURLConnection? = null

  override fun serviceType(intent: Intent): Int =
    if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING else 0

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
    while (scope.isActive) {
      try {
        if (!SignalStore.account.isRegistered) {
          delay(5_000)
          continue
        }
        val result = AppDependencies.accountApiV2.registerNtfyTopic()
        if (result !is RequestResult.Success) {
          throw IOException("Could not provision private ntfy topic")
        }
        val topic = result.result
        backoff = 2L
        // Read the durable cursor on *every* reconnect. If the stream throws
        // after enqueueing a wake, the in-memory return value is lost; using
        // only an initial cursor would reprocess the whole cache repeatedly.
        consumeStream(topic, loadCursor(topic))
      } catch (cancelled: CancellationException) {
        throw cancelled
      } catch (e: Exception) {
        // Do not log the private ntfy topic, URL with topic, or any auth token.
        Log.w(TAG, "Local ntfy stream interrupted; reconnecting")
      }
      if (!scope.isActive) break
      delay(backoff * 1000)
      backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
    }
  }

  /**
   * The topic is a secret bearer capability: never persist it in preferences.
   * Only its one-way SHA-256 fingerprint is stored alongside ntfy's opaque
   * event ID. On topic rotation the previous resume point is ignored.
   */
  private fun topicFingerprint(topic: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(topic.toByteArray(Charsets.UTF_8))
    return android.util.Base64.encodeToString(
      digest, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
    )
  }

  private fun loadCursor(topic: String): String? {
    val prefs = getSharedPreferences(CURSOR_PREFS, MODE_PRIVATE)
    if (prefs.getString(CURSOR_TOPIC_HASH, null) != topicFingerprint(topic)) return null
    return prefs.getString(CURSOR_MESSAGE_ID, null)?.takeIf {
      it.length in 1..64 && it.all { character -> character.isLetterOrDigit() || character == '_' || character == '-' }
    }
  }

  private fun persistCursor(topic: String, messageId: String) {
    if (messageId.length !in 1..64 || !messageId.all { it.isLetterOrDigit() || it == '_' || it == '-' }) return
    getSharedPreferences(CURSOR_PREFS, MODE_PRIVATE).edit()
      .putString(CURSOR_TOPIC_HASH, topicFingerprint(topic))
      .putString(CURSOR_MESSAGE_ID, messageId)
      .apply()
  }

  private fun configureTrust(conn: HttpsURLConnection) {
    val trustStore = LocalServerTrustStore(this)
    val store = KeyStore.getInstance("PKCS12")
    trustStore.keyStoreInputStream.use { store.load(it, trustStore.keyStorePassword.toCharArray()) }
    val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
    conn.sslSocketFactory = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }.socketFactory
    // The default platform hostname verifier remains unchanged.
  }

  private fun consumeStream(topic: String, resumeFrom: String?) {
    // The per-device topic is a high-entropy capability assigned only after
    // authenticated registration. It is not embedded in the APK or logs.
    val base = LocalServerConfig.load(this).ntfyBaseUrl
    val since = resumeFrom?.let { "?since=" + java.net.URLEncoder.encode(it, "UTF-8") } ?: "?since=all"
    val url = URL("$base/$topic/sse$since")
    val conn = (url.openConnection() as HttpsURLConnection).apply {
      configureTrust(this)
      requestMethod = "GET"
      instanceFollowRedirects = false
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
      if (conn.responseCode != 200) throw IOException("ntfy subscription failed (HTTP ${conn.responseCode})")
      conn.inputStream.bufferedReader().use { reader ->
        while (scope.isActive) {
          val line = reader.readLine() ?: break
          if (!line.startsWith("data:")) continue
          val body = line.removePrefix("data:").trim()
          val event = try { JSONObject(body) } catch (_: Exception) { continue }
          if (event.optString("event") != "message") continue
          val eventId = event.optString("id")
          if (eventId.isNotBlank() && eventId == last) continue
          when (event.optString("message")) {
            "wake" -> {
              // Queue durable encrypted-message retrieval first. Persisting
              // before enqueue would risk losing a wake if the process died.
              AppDependencies.jobManager.add(MessageFetchJob())
              if (eventId.isNotBlank()) {
                last = eventId
                persistCursor(topic, eventId)
              }
            }
            else -> {
              // No message contents, credentials or link previews are read
              // from ntfy. Other control events are intentionally ignored.
            }
          }
        }
      }
    } finally {
      conn.disconnect()
      if (connection === conn) connection = null
    }
  }
}
