package org.thoughtcrime.securesms.registration.local

import android.content.Context
import android.util.Base64
import org.thoughtcrime.securesms.push.LocalServerTrustStore
import org.json.JSONObject
import org.signal.network.api.RegistrationApiV2.SessionMetadata
import org.signal.registration.LocalAuthCodeBus
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.security.KeyStore
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Registration transport for Local Device Authentication.
 * The server returns a code only after the Android Keystore signature has been accepted.
 */
class LocalDeviceAuthClient(context: Context) {
  private val appContext = context.applicationContext
  private val config: LocalServerConfig
    get() = LocalServerConfig.load(appContext)
  private val keyStore = LocalDeviceAuthKeyStore(appContext)

  val isEnabled: Boolean
    get() = config.localAuthOnly

  fun isChallengeSession(sessionId: String): Boolean = sessionId.startsWith(CHALLENGE_PREFIX)

  fun isCompletedLocalSession(sessionId: String): Boolean {
    return try {
      val bytes = Base64.decode(sessionId, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
      String(bytes, StandardCharsets.UTF_8).startsWith("LAN1.")
    } catch (_: IllegalArgumentException) {
      false
    }
  }

  suspend fun createSession(phone: String): SessionMetadata = withContext(Dispatchers.IO) {
    // Create the stable hardware-backed key before the admin enrollment handshake.
    keyStore.getOrCreateKeyPair()
    val challenge = post(
      "/v1/local-auth/challenge",
      JSONObject()
        .put("phone", phone)
        .put("androidId", keyStore.androidId())
    )
    val challengeId = challenge.getString("challengeId")
    val nonce = challenge.getString("nonce")
    val state = JSONObject()
      .put("challengeId", challengeId)
      .put("nonce", nonce)
      .put("phone", phone)
    val encodedState = Base64.encodeToString(
      state.toString().toByteArray(StandardCharsets.UTF_8),
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    )
    SessionMetadata(
      id = CHALLENGE_PREFIX + encodedState,
      nextSms = null,
      nextCall = null,
      nextVerificationAttempt = null,
      allowedToRequestCode = true,
      requestedInformation = emptyList(),
      verified = false
    )
  }

  suspend fun requestCode(sessionId: String): SessionMetadata = withContext(Dispatchers.IO) {
    val state = decodeState(sessionId)
    val challengeId = state.getString("challengeId")
    val phone = state.getString("phone")
    val nonce = state.getString("nonce")
    keyStore.getOrCreateKeyPair()
    val signature = keyStore.signCanonicalChallenge(challengeId, phone, nonce)
    val response = post(
      "/v1/local-auth/verify",
      JSONObject()
        .put("challengeId", challengeId)
        .put("signature", signature)
    )
    val code = response.getString("verificationCode")
    require(code.length == 6 && code.all(Char::isDigit)) { "Local authentication service returned an invalid code" }
    LocalAuthCodeBus.publish(sessionId, code)
    SessionMetadata(
      id = sessionId,
      nextSms = null,
      nextCall = null,
      nextVerificationAttempt = null,
      allowedToRequestCode = false,
      requestedInformation = emptyList(),
      verified = false
    )
  }

  suspend fun submitCode(sessionId: String, code: String): SessionMetadata = withContext(Dispatchers.IO) {
    val state = decodeState(sessionId)
    val response = post(
      "/v1/local-auth/complete",
      JSONObject()
        .put("challengeId", state.getString("challengeId"))
        .put("code", code)
    )
    SessionMetadata(
      id = response.getString("sessionId"),
      nextSms = null,
      nextCall = null,
      nextVerificationAttempt = null,
      allowedToRequestCode = false,
      requestedInformation = emptyList(),
      verified = true
    )
  }

  fun exportDeviceEnrollmentPublicKey(): String = keyStore.publicKeyPem()

  private fun decodeState(sessionId: String): JSONObject {
    require(isChallengeSession(sessionId)) { "Not a local authentication challenge" }
    val encoded = sessionId.removePrefix(CHALLENGE_PREFIX)
    val bytes = Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    return JSONObject(String(bytes, StandardCharsets.UTF_8))
  }

  private fun configureLanTrust(connection: HttpsURLConnection) {
    val trustStore = LocalServerTrustStore(appContext)
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
    // Keep the platform's default hostname verifier; never accept a certificate for another host.
  }

  private fun post(path: String, body: JSONObject): JSONObject {
    val base = config.localAuthApiUrl
    val url = URL(base + path)
    val connection = (url.openConnection() as HttpURLConnection).apply {
      if (this is HttpsURLConnection) {
        configureLanTrust(this)
      }
      requestMethod = "POST"
      connectTimeout = 8_000
      readTimeout = 8_000
      doOutput = true
      setRequestProperty("Content-Type", "application/json")
      setRequestProperty("Accept", "application/json")
      useCaches = false
    }
    try {
      OutputStreamWriter(connection.outputStream, StandardCharsets.UTF_8).use { writer ->
        writer.write(body.toString())
      }
      val status = connection.responseCode
      val stream = if (status in 200..299) connection.inputStream else connection.errorStream
      val payload = stream?.bufferedReader(StandardCharsets.UTF_8)?.use { it.readText() }.orEmpty()
      val json = if (payload.isBlank()) JSONObject() else JSONObject(payload)
      if (status !in 200..299) {
        throw IllegalStateException(json.optString("error").ifBlank { "Local authentication failed (HTTP $status)" })
      }
      return json
    } finally {
      connection.disconnect()
    }
  }

  companion object {
    private const val CHALLENGE_PREFIX = "LOCAL1."
  }
}
