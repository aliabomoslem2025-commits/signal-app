/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.thoughtcrime.securesms.push

import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.signal.core.util.logging.Log
import org.signal.libsignal.net.RequestResult
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.messages.WebSocketDrainer
import org.thoughtcrime.securesms.net.SignalNetwork
import org.thoughtcrime.securesms.notifications.NotificationChannels
import org.thoughtcrime.securesms.notifications.NotificationIds
import org.thoughtcrime.securesms.registration.local.LocalServerConfig
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.math.min
import kotlin.random.Random

/**
 * Direct, self-hosted ntfy subscription for LAN deployments.
 *
 * ntfy carries only the literal "wake" hint. The message envelope is still fetched over Signal's
 * authenticated WebSocket and decrypted by the existing Signal protocol stack.
 */
class NtfyPushService : Service() {
  companion object {
    private val TAG = Log.tag(NtfyPushService::class.java)
    private const val PREFS = "ntfy_push_state"
    private const val LAST_MESSAGE_ID = "last_message_id"
    private const val KEEP_ALIVE_TOKEN = "NtfyPush"
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val WEBSOCKET_DRAIN_TIMEOUT_MS = 90_000L
    private const val RETRY_MIN_MS = 1_000L
    private const val RETRY_MAX_MS = 60_000L

    @JvmStatic
    fun startIfConfigured(context: Context) {
      if (!SignalStore.account.isRegistered) return
      val config = try {
        LocalServerConfig.load(context)
      } catch (e: Exception) {
        Log.w(TAG, "Cannot load LAN push configuration", e)
        return
      }
      if (!config.isNtfyPushConfigured) return
      try {
        ContextCompat.startForegroundService(context, Intent(context, NtfyPushService::class.java))
      } catch (e: Exception) {
        Log.w(TAG, "Unable to start the private ntfy push service", e)
      }
    }

    @JvmStatic
    fun stop(context: Context) {
      context.stopService(Intent(context, NtfyPushService::class.java))
    }
  }

  @Volatile private var running = false
  @Volatile private var activeConnection: HttpURLConnection? = null
  private var worker: Thread? = null

  override fun onCreate() {
    super.onCreate()
    startForeground(NotificationIds.NTFY_PUSH_SERVICE, buildForegroundNotification())
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (!running) {
      running = true
      worker = Thread(::runSubscriptionLoop, "SignalNtfySubscription").apply {
        isDaemon = true
        start()
      }
    }
    return START_STICKY
  }

  override fun onDestroy() {
    running = false
    activeConnection?.disconnect()
    worker?.interrupt()
    worker = null
    super.onDestroy()
  }

  override fun onBind(intent: Intent?): IBinder? = null

  private fun buildForegroundNotification(): Notification {
    return NotificationCompat.Builder(this, NotificationChannels.getInstance().OTHER)
      .setSmallIcon(R.drawable.ic_signal_refresh)
      .setContentTitle(getString(R.string.app_name))
      .setContentText("Private LAN message connection active")
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setOngoing(true)
      .setOnlyAlertOnce(true)
      .setVibrate(longArrayOf(0))
      .build()
  }

  private fun runSubscriptionLoop() {
    var retryDelay = RETRY_MIN_MS
    while (running && SignalStore.account.isRegistered) {
      try {
        subscribeOnce()
        retryDelay = RETRY_MIN_MS
      } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        break
      } catch (e: Exception) {
        if (running) Log.w(TAG, "ntfy stream disconnected; reconnecting", e)
      } finally {
        activeConnection?.disconnect()
        activeConnection = null
      }

      if (running) {
        val jitter = Random.nextLong(0L, maxOf(1L, retryDelay / 4))
        try {
          Thread.sleep(retryDelay + jitter)
        } catch (_: InterruptedException) {
          Thread.currentThread().interrupt()
          break
        }
        retryDelay = min(RETRY_MAX_MS, retryDelay * 2)
      }
    }
    stopSelf()
  }

  private fun subscribeOnce() {
    if (!SignalStore.account.isRegistered) return
    val config = LocalServerConfig.load(this)
    val baseUrl = config.ntfyBaseUrl ?: throw IOException("services.ntfy is not configured")
    val readerToken = config.ntfyReaderToken.takeIf { it.isNotBlank() }
      ?: throw IOException("ntfy reader token is not configured")

    val topic = runBlocking(Dispatchers.IO) {
      when (val result = SignalNetwork.accountApiV2.registerNtfyTopic()) {
        is RequestResult.Success -> result.result
        is RequestResult.ApplicationError -> throw IOException("Could not register this device's ntfy topic", result.cause)
        is RequestResult.RetryableNetworkError -> throw IOException("Could not register this device's ntfy topic", result.exception)
        else -> throw IOException("Signal Server rejected ntfy topic registration")
      }
    }
    require(topic.matches(Regex("[A-Za-z0-9_-]{32,128}"))) { "Signal Server returned an invalid ntfy topic" }

    val preferences = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val lastId = preferences.getString(LAST_MESSAGE_ID, null)
    val query = if (lastId.isNullOrBlank()) "since=all" else "since=" + Uri.encode(lastId)
    val url = URL(baseUrl.trimEnd('/') + "/" + topic + "/json?" + query)

    val connection = (url.openConnection() as HttpURLConnection).apply {
      if (this is HttpsURLConnection) configureLanTrust(this)
      requestMethod = "GET"
      connectTimeout = CONNECT_TIMEOUT_MS
      readTimeout = 0
      setRequestProperty("Authorization", "Bearer " + readerToken)
      setRequestProperty("Accept", "application/x-ndjson")
      setRequestProperty("Cache-Control", "no-cache")
      useCaches = false
    }
    activeConnection = connection

    val status = connection.responseCode
    if (status !in 200..299) {
      val message = connection.errorStream?.bufferedReader(StandardCharsets.UTF_8)?.use { it.readText() }.orEmpty()
      throw IOException("ntfy subscription failed with HTTP " + status + " " + message.take(160))
    }

    BufferedReader(InputStreamReader(connection.inputStream, StandardCharsets.UTF_8)).use { reader ->
      while (running) {
        val line = reader.readLine() ?: throw IOException("ntfy stream ended")
        if (line.isBlank()) continue
        val event = try {
          JSONObject(line)
        } catch (e: Exception) {
          Log.w(TAG, "Ignoring malformed ntfy event", e)
          continue
        }
        if (event.optString("event") != "message") continue

        val messageId = event.optString("id")
        val payload = event.optString("message")
        if (payload == "wake") {
          // Do not acknowledge the ntfy event until Signal's authenticated receive path drains.
          val drained = WebSocketDrainer.blockUntilDrainedAndProcessed(
            WEBSOCKET_DRAIN_TIMEOUT_MS,
            KEEP_ALIVE_TOKEN
          )
          if (!drained) throw IOException("Signal WebSocket did not drain after ntfy wake hint")
        }

        if (messageId.isNotBlank()) {
          preferences.edit().putString(LAST_MESSAGE_ID, messageId).apply()
        }
      }
    }
  }

  private fun configureLanTrust(connection: HttpsURLConnection) {
    val trustStore = LocalServerTrustStore(this)
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    trustStore.getKeyStoreInputStream().use { input ->
      keyStore.load(input, trustStore.getKeyStorePassword().toCharArray())
    }
    val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
      init(keyStore)
    }
    val sslContext = SSLContext.getInstance("TLS").apply {
      init(null, trustManagers.trustManagers, null)
    }
    connection.sslSocketFactory = sslContext.socketFactory
    // The platform hostname verifier remains enabled.
  }
}
