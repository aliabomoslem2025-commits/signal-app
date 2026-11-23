package org.thoughtcrime.securesms.registration.local

import android.content.Context
import org.json.JSONObject
import org.thoughtcrime.securesms.push.LocalServerTrustStore
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.Proxy
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/** Direct private HTTPS only; redirects and proxy/public fallbacks are disabled. */
class LanHttpClient(context: Context) {
  private val socketFactory = run {
    val source = LocalServerTrustStore(context.applicationContext)
    val store = KeyStore.getInstance("PKCS12")
    source.keyStoreInputStream.use { store.load(it, source.keyStorePassword.toCharArray()) }
    val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
    SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }.socketFactory
  }

  data class Response(val status: Int, val body: JSONObject, val retryAfterSeconds: Int? = null)

  @Throws(IOException::class)
  fun request(origin: String, path: String, method: String, authorization: String, body: JSONObject? = null, timeoutMs: Int = 10_000): Response {
    require(path.startsWith('/') && !path.startsWith("//") && !path.contains('?'))
    val target = URL(origin.trimEnd('/') + path)
    require(target.protocol == "https" && target.userInfo == null && target.ref == null)
    val connection = (target.openConnection(Proxy.NO_PROXY) as HttpsURLConnection).apply {
      sslSocketFactory = socketFactory
      instanceFollowRedirects = false
      requestMethod = method
      connectTimeout = timeoutMs.coerceIn(1000, 30_000)
      readTimeout = timeoutMs.coerceIn(1000, 30_000)
      useCaches = false
      setRequestProperty("Accept", "application/json")
      setRequestProperty("Authorization", authorization)
      if (body != null) {
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
      }
    }
    try {
      if (body != null) {
        val payload = body.toString().toByteArray(StandardCharsets.UTF_8)
        connection.setFixedLengthStreamingMode(payload.size)
        connection.outputStream.use { it.write(payload) }
      }
      val status = connection.responseCode
      if (status in 300..399) throw IOException("LAN redirects are refused")
      val stream = if (status in 200..299) connection.inputStream else connection.errorStream
      val bytes = ByteArrayOutputStream()
      stream?.use { input ->
        val chunk = ByteArray(4096)
        while (true) {
          val count = input.read(chunk)
          if (count < 0) break
          if (bytes.size() + count > 65_536) throw IOException("LAN response exceeds size limit")
          bytes.write(chunk, 0, count)
        }
      }
      val text = bytes.toString(StandardCharsets.UTF_8.name())
      val parsed = try {
        if (text.isBlank()) JSONObject() else JSONObject(text)
      } catch (_: Exception) {
        throw IOException("Invalid LAN JSON response")
      }
      return Response(status, parsed, connection.getHeaderField("Retry-After")?.toIntOrNull()?.coerceIn(1, 86400))
    } finally {
      connection.disconnect()
    }
  }
}
