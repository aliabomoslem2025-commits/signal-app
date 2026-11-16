package org.thoughtcrime.securesms.registration.local

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import org.signal.network.api.RegistrationApiV2.SessionMetadata
import org.signal.registration.LanDeviceNotAuthorizedException
import org.signal.registration.LocalAuthCodeBus
import org.thoughtcrime.securesms.push.LocalServerTrustStore
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Device-only registration transport for the self-hosted Go local-auth sidecar.
 * Does not use SMS or the public Signal registration service.
 *
 * The code is not sufficient without a second Keystore signature at completion.
 */
class LocalDeviceAuthClient(context: Context) {
  private val app = context.applicationContext
  private val enrollmentKey = LocalDeviceAuthKeyStore(app)
  private val config: LocalServerConfig get() = LocalServerConfig.load(app)

  fun isChallengeSession(id: String): Boolean = id.startsWith(LocalAuthCodeBus.CHALLENGE_SESSION_PREFIX)

  fun isCompletedSession(id: String): Boolean = try {
    val bytes = Base64.decode(id, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    String(bytes, StandardCharsets.UTF_8).startsWith("LAN1.")
  } catch (_: Exception) {
    false
  }

  suspend fun createSession(phone: String): SessionMetadata = withContext(Dispatchers.IO) {
    enrollmentKey.getOrCreateKeyPair()
    val challenge = post(
      "/v1/local-auth/challenge",
      JSONObject().put("phone", phone).put("androidId", enrollmentKey.androidId())
    )
    val state = JSONObject()
      .put("challengeId", challenge.getString("challengeId"))
      .put("nonce", challenge.getString("nonce"))
      .put("phone", phone)
    val id = LocalAuthCodeBus.CHALLENGE_SESSION_PREFIX + Base64.encodeToString(
      state.toString().toByteArray(StandardCharsets.UTF_8),
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    )
    metadata(id, allowed = true, verified = false)
  }

  suspend fun requestCode(id: String): SessionMetadata = withContext(Dispatchers.IO) {
    val state = decodeChallenge(id)
    val challengeId = state.getString("challengeId")
    val phone = state.getString("phone")
    val nonce = state.getString("nonce")
    val signature = enrollmentKey.signChallenge(challengeId, phone, nonce)
    val response = post(
      "/v1/local-auth/verify",
      JSONObject().put("challengeId", challengeId).put("signature", signature)
    )
    val code = response.getString("verificationCode")
    require(code.length == 6 && code.all { it in '0'..'9' }) { "Invalid LAN activation response" }
    LocalAuthCodeBus.publish(id, code)
    metadata(id, allowed = false, verified = false)
  }

  suspend fun complete(id: String, code: String): SessionMetadata = withContext(Dispatchers.IO) {
    val state = decodeChallenge(id)
    val challengeId = state.getString("challengeId")
    val signature = enrollmentKey.signCompletion(
      challengeId, state.getString("phone"), state.getString("nonce"), code
    )
    val response = post(
      "/v1/local-auth/complete",
      JSONObject().put("challengeId", challengeId).put("code", code).put("signature", signature)
    )
    val ticketId = response.getString("sessionId")
    require(isCompletedSession(ticketId)) { "Local authorization returned an invalid signed session" }
    LocalAuthCodeBus.consume(id, code)
    metadata(ticketId, allowed = false, verified = true)
  }

  fun enrollmentInformation(): JSONObject = JSONObject()
    .put("androidId", enrollmentKey.androidId())
    .put("publicKeyPem", enrollmentKey.publicKeyPem())

  private fun metadata(id: String, allowed: Boolean, verified: Boolean) =
    SessionMetadata(
      id = id,
      nextSms = null,
      nextCall = null,
      nextVerificationAttempt = null,
      allowedToRequestCode = allowed,
      requestedInformation = emptyList(),
      verified = verified
    )

  private fun decodeChallenge(id: String): JSONObject {
    require(isChallengeSession(id)) { "Not an enrolled LAN challenge" }
    val bytes = Base64.decode(
      id.removePrefix(LocalAuthCodeBus.CHALLENGE_SESSION_PREFIX),
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    )
    return JSONObject(String(bytes, StandardCharsets.UTF_8))
  }

  private fun post(path: String, body: JSONObject): JSONObject {
    val url = URL(config.localAuthApiUrl + path)
    require(url.protocol.equals("https", true)) { "Local authentication must use HTTPS" }
    val connection = (url.openConnection() as HttpsURLConnection).apply {
      // Java's platform hostname verification stays enabled; only the explicit
      // bundled LAN CA is trusted. Do not disable certificate validation.
      val trustStore = LocalServerTrustStore(app)
      val store = KeyStore.getInstance("PKCS12")
      trustStore.keyStoreInputStream.use { input ->
        store.load(input, trustStore.keyStorePassword.toCharArray())
      }
      val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
      val tls = SSLContext.getInstance("TLS").apply { init(null, trustManagers.trustManagers, null) }
      sslSocketFactory = tls.socketFactory
      requestMethod = "POST"
      connectTimeout = 8000
      readTimeout = 8000
      doOutput = true
      useCaches = false
      setRequestProperty("Content-Type", "application/json")
      setRequestProperty("Accept", "application/json")
    }
    try {
      connection.outputStream.use { it.write(body.toString().toByteArray(StandardCharsets.UTF_8)) }
      val status = connection.responseCode
      val stream = if (status in 200..299) connection.inputStream else connection.errorStream
      val response = stream?.bufferedReader(StandardCharsets.UTF_8)?.use { it.readText() }.orEmpty()
      val parsed = if (response.isBlank()) JSONObject() else JSONObject(response)
      if (status == HttpURLConnection.HTTP_UNAUTHORIZED || status == HttpURLConnection.HTTP_FORBIDDEN) {
        throw LanDeviceNotAuthorizedException()
      }
      if (status !in 200..299) {
        throw IllegalStateException("LAN authentication failed (HTTP $status)")
      }
      return parsed
    } finally {
      connection.disconnect()
    }
  }
}
