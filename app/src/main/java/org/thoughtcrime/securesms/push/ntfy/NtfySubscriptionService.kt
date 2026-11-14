package org.thoughtcrime.securesms.push.ntfy

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import org.signal.core.util.PendingIntentFlags
import org.signal.core.util.logging.Log
import org.thoughtcrime.securesms.MainActivity
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.jobs.MessageFetchJob
import org.thoughtcrime.securesms.jobs.SubmitRateLimitPushChallengeJob
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.messages.WebSocketDrainer
import org.thoughtcrime.securesms.network.local.LocalServerConfig
import org.thoughtcrime.securesms.network.local.LocalServerConfigStore
import org.thoughtcrime.securesms.network.local.LocalServerTrustStore
import org.thoughtcrime.securesms.notifications.NotificationChannels
import org.thoughtcrime.securesms.notifications.NotificationIds
import org.thoughtcrime.securesms.registration.ntfy.PushChallengeRequest
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.Executors
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Maintains the authenticated ntfy JSON stream as a foreground service. ntfy events are only
 * wake-up/control hints; actual Signal envelopes are fetched over Signal's authenticated channel.
 */
class NtfySubscriptionService : Service() {

  companion object {
    private val TAG = Log.tag(NtfySubscriptionService::class.java)
    private const val NOTIFICATION_ID = NotificationIds.NTFY_SUBSCRIPTION
    private const val KEEP_ALIVE_TOKEN = "NtfyPushFetch"
    private const val MAX_BACKOFF_MS = 60_000L
    @Volatile private var connected = false
    private val connectedLatch = CountDownLatch(1)

    fun awaitConnected(timeoutMs: Long): Boolean {
      return connected || connectedLatch.await(timeoutMs, TimeUnit.MILLISECONDS)
    }

    fun start(context: Context) {
      ContextCompat.startForegroundService(context, Intent(context, NtfySubscriptionService::class.java))
    }

    fun stop(context: Context) {
      context.stopService(Intent(context, NtfySubscriptionService::class.java))
    }
  }

  @Volatile private var running = false
  @Volatile private var currentResponse: Response? = null
  private val subscriptionStarted = AtomicBoolean(false)
  private var subscriptionExecutor: ExecutorService? = null
  private var fetchExecutor: ExecutorService? = null

  override fun onCreate() {
    super.onCreate()
    running = true
    subscriptionExecutor = Executors.newSingleThreadExecutor { runnable ->
      Thread(runnable, "NtfySubscription").apply { isDaemon = true }
    }
    fetchExecutor = Executors.newSingleThreadExecutor { runnable ->
      Thread(runnable, "NtfySignalFetch").apply { isDaemon = true }
    }
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    startForeground(NOTIFICATION_ID, buildForegroundNotification())
    val config = runCatching { LocalServerConfigStore.load(this) }.getOrElse {
      Log.w(TAG, "Unable to read LAN configuration; ntfy subscription will stop", it)
      stopSelf(startId)
      return START_NOT_STICKY
    }
    val topic = SignalStore.account.ntfyTopic
    if (topic.isNullOrBlank() || config.ntfyReaderToken.isBlank()) {
      Log.w(TAG, "ntfy topic or reader token is missing; subscription will not start")
      stopSelf(startId)
      return START_NOT_STICKY
    }

    if (subscriptionStarted.compareAndSet(false, true)) {
      subscriptionExecutor?.execute { subscribeLoop(config, topic) }
    }
    return START_STICKY
  }

  private fun buildForegroundNotification() =
    NotificationCompat.Builder(this, NotificationChannels.getInstance().OTHER)
      .setSmallIcon(R.drawable.ic_signal_refresh)
      .setContentTitle(getString(R.string.app_name))
      .setContentText("اتصال اعلان‌های پیام‌رسان محلی فعال است")
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setOnlyAlertOnce(true)
      .setOngoing(true)
      .setContentIntent(PendingIntent.getActivity(this, 0, MainActivity.clearTop(this), PendingIntentFlags.mutable()))
      .build()

  private fun subscribeLoop(config: LocalServerConfig, topic: String) {
    var backoff = 1_000L
    while (running) {
      try {
        val client = buildClient(config)
        val url = "${config.ntfyBaseUrl.trimEnd('/')}/$topic/json?since=all"
        val request = Request.Builder()
          .url(url)
          .header("Authorization", "Bearer ${config.ntfyReaderToken}")
          .header("Accept", "application/x-ndjson")
          .get()
          .build()

        client.newCall(request).execute().use { response ->
          currentResponse = response
          if (!response.isSuccessful) {
            throw IOException("ntfy returned HTTP ${response.code}")
          }
          connected = true
          connectedLatch.countDown()
          // Signal Server keeps the actual encrypted messages in its own queue. Fetch on every
          // successful (re)connection so a device that temporarily lost its ntfy stream still
          // catches up even when wake hints were not cached by ntfy.
          enqueueSignalFetch()
          val source = response.body?.source() ?: throw IOException("ntfy returned an empty response body")
          backoff = 1_000L
          while (running) {
            val line = source.readUtf8Line() ?: break
            if (line.isNotBlank()) handleNtfyLine(line)
          }
        }
        currentResponse = null
        if (running) throw IOException("ntfy stream closed")
      } catch (e: Exception) {
        currentResponse = null
        if (running) Log.w(TAG, "ntfy stream disconnected; reconnecting", e)
      }

      if (running) {
        val jitter = ThreadLocalRandom.current().nextLong(0L, (backoff / 3L).coerceAtLeast(1L))
        try {
          Thread.sleep(backoff + jitter)
        } catch (_: InterruptedException) {
          Thread.currentThread().interrupt()
          return
        }
        backoff = (backoff * 2L).coerceAtMost(MAX_BACKOFF_MS)
      }
    }
  }

  private fun buildClient(config: LocalServerConfig): OkHttpClient {
    val certificateFactory = CertificateFactory.getInstance("X.509")
    val certificates = certificateFactory.generateCertificates(config.caCertificatePem.byteInputStream())
    require(certificates.isNotEmpty()) { "No LAN CA certificate was configured" }

    val keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType()).apply {
      load(null, null)
      certificates.forEachIndexed { index, certificate ->
        setCertificateEntry("ntfy-lan-ca-$index", certificate)
      }
    }
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
      init(keyStore)
    }
    val trustManager = trustManagerFactory.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
      ?: throw IllegalStateException("No X509 trust manager is available")
    val sslContext = SSLContext.getInstance("TLS").apply {
      init(null, arrayOf(trustManager), SecureRandom())
    }

    return OkHttpClient.Builder()
      .sslSocketFactory(sslContext.socketFactory, trustManager)
      .connectTimeout(10, TimeUnit.SECONDS)
      .readTimeout(0, TimeUnit.MILLISECONDS)
      .writeTimeout(10, TimeUnit.SECONDS)
      .retryOnConnectionFailure(true)
      .build()
  }

  private fun handleNtfyLine(line: String) {
    try {
      val envelope = JSONObject(line)
      if (envelope.optString("event") != "message") return
      val message = envelope.optString("message")
      if (message == "wake" || message.isBlank()) {
        enqueueSignalFetch()
        return
      }

      val control = runCatching { JSONObject(message) }.getOrNull()
      if (control == null) {
        // Unknown or malformed hints are treated as wake-up signals, never as chat content.
        enqueueSignalFetch()
        return
      }

      when (control.optString("type")) {
        "CHALLENGE" -> control.optString("data").takeIf { it.isNotBlank() }?.let(PushChallengeRequest::postChallengeResponse)
        "RATE_LIMIT_CHALLENGE" -> control.optString("data").takeIf { it.isNotBlank() }?.let {
          AppDependencies.getJobManager().add(SubmitRateLimitPushChallengeJob(it))
        }
        "VERIFICATION_CODE_REQUESTED" -> {
          if (SignalStore.account.isPrimaryDevice) {
            val data = control.optJSONObject("data")
            val requestedAt = data?.optLong("timestamp", envelope.optLong("time", System.currentTimeMillis()))
              ?: envelope.optLong("time", System.currentTimeMillis())
            SignalStore.account.setVerificationCodeRequestedAtMs(requestedAt)
          }
        }
        else -> enqueueSignalFetch()
      }
    } catch (e: Exception) {
      Log.w(TAG, "Unable to process ntfy event; scheduling a normal Signal fetch", e)
      enqueueSignalFetch()
    }
  }

  private fun enqueueSignalFetch() {
    fetchExecutor?.execute {
      val drained = runCatching {
        WebSocketDrainer.blockUntilDrainedAndProcessed(5 * 60 * 1000L, KEEP_ALIVE_TOKEN)
      }.getOrElse {
        Log.w(TAG, "Signal websocket drain failed after ntfy wake-up", it)
        false
      }
      if (!drained) {
        AppDependencies.getJobManager().add(MessageFetchJob())
      }
    }
  }

  override fun onDestroy() {
    running = false
    subscriptionStarted.set(false)
    connected = false
    currentResponse?.close()
    subscriptionExecutor?.shutdownNow()
    fetchExecutor?.shutdownNow()
    stopForeground(true)
    subscriptionExecutor = null
    fetchExecutor = null
    super.onDestroy()
  }

  override fun onBind(intent: Intent?): IBinder? = null
}
