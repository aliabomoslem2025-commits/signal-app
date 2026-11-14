package org.thoughtcrime.securesms.registration.v2.localauth

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.thoughtcrime.securesms.network.local.LocalServerConfig
import org.thoughtcrime.securesms.network.local.LocalServerConfigStore
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Client for the LAN-only device challenge protocol. Android ID is an allow-list lookup hint;
 * the enrolled, non-exportable Android Keystore key proves possession of the approved device.
 */
class LocalDeviceAuthClient(context: Context) {
  private val appContext = context.applicationContext
  private val config = LocalServerConfigStore.load(appContext)
  private val httpClient = buildHttpClient(config)

  data class ChallengeResult(val challengeId: String, val verificationCode: String)

  fun beginRegistration(e164: String): ChallengeResult {
    require(e164.matches(Regex("^\\+[1-9][0-9]{7,14}$"))) { "شماره تلفن باید در قالب بین‌المللی باشد." }
    val androidId = getAndroidId()
    val keyPair = getOrCreateKeyPair()

    val challenge = post("/v1/local-auth/challenge", JSONObject().apply {
      put("phone", e164)
      put("androidId", androidId)
    })
    val challengeId = challenge.getString("challengeId")
    val nonce = challenge.getString("nonce")
    val canonicalMessage = "signal-local-auth-v1\\n$challengeId\\n$e164\\n$nonce"
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(keyPair.private)
    signer.update(canonicalMessage.toByteArray(Charsets.UTF_8))
    val signature = Base64.encodeToString(signer.sign(), Base64.NO_WRAP)

    val verified = post("/v1/local-auth/verify", JSONObject().apply {
      put("challengeId", challengeId)
      put("signature", signature)
    })
    val code = verified.getString("verificationCode")
    require(code.length == 6 && code.all(Char::isDigit)) { "سرور کد احراز هویت نامعتبر برگرداند." }
    return ChallengeResult(challengeId, code)
  }

  fun completeVerification(challengeId: String, code: String): String {
    require(code.length == 6 && code.all(Char::isDigit)) { "کد احراز هویت باید شش رقم باشد." }
    val response = post("/v1/local-auth/complete", JSONObject().apply {
      put("challengeId", challengeId)
      put("code", code)
    })
    val sessionId = response.getString("sessionId")
    require(sessionId.isNotBlank() && sessionId.length <= 4096) { "توکن ثبت‌نام سرور نامعتبر است." }
    return sessionId
  }

  /**
   * Export only public enrollment data for the administrator dashboard.
   * The Keystore private key is never serialized or returned.
   */
  fun exportEnrollmentJson(): String {
    val keyPair = getOrCreateKeyPair()
    val pem = buildString {
      append("-----BEGIN PUBLIC KEY-----\\n")
      append(Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP))
      append("\\n-----END PUBLIC KEY-----")
    }
    return JSONObject().apply {
      put("androidId", getAndroidId())
      put("publicKeyPem", pem)
      put("label", Build.MODEL ?: "Android device")
      put("keyAlgorithm", "ECDSA-P256")
    }.toString(2)
  }

  private fun getAndroidId(): String {
    val value = Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID)
    require(!value.isNullOrBlank()) { "Android ID این دستگاه در دسترس نیست." }
    return value
  }

  private fun getOrCreateKeyPair(): KeyPair {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val existingPrivateKey = keyStore.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
    val existingCertificate = keyStore.getCertificate(KEY_ALIAS)
    if (existingPrivateKey != null && existingCertificate != null) {
      return KeyPair(existingCertificate.publicKey, existingPrivateKey)
    }

    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
    generator.initialize(
      KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
        .build()
    )
    return generator.generateKeyPair()
  }

  private fun post(path: String, payload: JSONObject): JSONObject {
    val endpoint = config.localAuthUrl.trimEnd('/') + path
    val request = Request.Builder()
      .url(endpoint)
      .header("Accept", "application/json")
      .post(payload.toString().toRequestBody(JSON_MEDIA_TYPE))
      .build()

    httpClient.newCall(request).execute().use { response ->
      val body = response.body?.string().orEmpty()
      if (!response.isSuccessful) {
        val message = try {
          JSONObject(body).optString("error", "HTTP ${response.code}")
        } catch (_: Exception) {
          "HTTP ${response.code}"
        }
        throw IOException("Local authentication failed: $message")
      }
      return try {
        JSONObject(body)
      } catch (error: Exception) {
        throw IOException("Local authentication service returned invalid JSON.", error)
      }
    }
  }

  private fun buildHttpClient(config: LocalServerConfig): OkHttpClient {
    config.validate()
    val certificateFactory = CertificateFactory.getInstance("X.509")
    val certificates = certificateFactory.generateCertificates(
      ByteArrayInputStream(config.caCertificatePem.toByteArray(Charsets.US_ASCII))
    )
    require(certificates.isNotEmpty()) { "گواهی CA محلی معتبر نیست." }

    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
      load(null, TRUST_STORE_PASSWORD)
      certificates.forEachIndexed { index, certificate ->
        setCertificateEntry("signal-lan-ca-$index", certificate)
      }
    }
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(keyStore)
    val trustManager = trustManagerFactory.trustManagers.filterIsInstance<X509TrustManager>().singleOrNull()
      ?: throw IllegalStateException("X.509 trust manager is unavailable.")
    val sslContext = SSLContext.getInstance("TLS").apply {
      init(null, arrayOf(trustManager), null)
    }

    return OkHttpClient.Builder()
      .sslSocketFactory(sslContext.socketFactory, trustManager)
      .connectTimeout(8, TimeUnit.SECONDS)
      .readTimeout(10, TimeUnit.SECONDS)
      .writeTimeout(10, TimeUnit.SECONDS)
      .callTimeout(15, TimeUnit.SECONDS)
      .retryOnConnectionFailure(false)
      .build()
  }

  companion object {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "signal_lan_local_auth_ecdsa_p256_v1"
    private val TRUST_STORE_PASSWORD = "signal-local-ca".toCharArray()
    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
  }
}