package org.thoughtcrime.securesms.pin

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import org.signal.core.models.MasterKey
import org.thoughtcrime.securesms.pin.lan.LanRecoveryCrypto
import org.thoughtcrime.securesms.registration.local.LanHttpClient
import org.thoughtcrime.securesms.registration.local.LocalServerConfig
import org.whispersystems.signalservice.api.svr.SecureValueRecovery
import org.whispersystems.signalservice.api.svr.SecureValueRecovery.BackupResponse
import org.whispersystems.signalservice.api.svr.SecureValueRecovery.DeleteResponse
import org.whispersystems.signalservice.api.svr.SecureValueRecovery.PinChangeSession
import org.whispersystems.signalservice.api.svr.SecureValueRecovery.RestoreResponse
import org.whispersystems.signalservice.api.svr.SecureValueRecovery.SvrVersion
import org.whispersystems.signalservice.internal.push.AuthCredentials
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.UUID

/** Software recovery transport, explicitly separate from attested SVR2/SVR3. */
class LanSecureValueRecovery(context: Context, private val fetchAuthorization: () -> AuthCredentials) : SecureValueRecovery {
  private val app = context.applicationContext
  private val http by lazy { LanHttpClient(app) }
  private val origin get() = LocalServerConfig.load(app).svr2Url

  override val svrVersion = SvrVersion.SOFTWARE_LAN

  override fun authorization(): AuthCredentials = fetchAuthorization()

  override fun setPin(userPin: String, masterKey: MasterKey): PinChangeSession = Session(userPin, masterKey)

  override fun resumePinChangeSession(userPin: String, masterKey: MasterKey, serializedChangeSession: String): PinChangeSession {
    return try {
      val state = JSONObject(serializedChangeSession)
      if (state.optInt("format") == 1 && state.optString("intent") == intent(userPin, masterKey)) {
        Session(userPin, masterKey, state)
      } else {
        setPin(userPin, masterKey)
      }
    } catch (_: Exception) {
      setPin(userPin, masterKey)
    }
  }

  override fun restoreDataPreRegistration(authorization: AuthCredentials, shareSet: ByteArray?, userPin: String): RestoreResponse =
    restore(authorization, userPin)

  override fun restoreDataPostRegistration(userPin: String): RestoreResponse = try {
    restore(authorization(), userPin)
  } catch (e: IOException) {
    RestoreResponse.NetworkError(e)
  }

  override fun deleteData(): DeleteResponse = try {
    val response = http.request(origin, "/v1/lan-recovery/backup", "DELETE", authorization().asBasic())
    when (response.status) {
      204 -> DeleteResponse.Success
      else -> DeleteResponse.ApplicationError(IOException("LAN recovery deletion HTTP ${response.status}"))
    }
  } catch (e: IOException) {
    DeleteResponse.NetworkError(e)
  } catch (e: Exception) {
    DeleteResponse.ApplicationError(e)
  }

  private fun restore(auth: AuthCredentials, pin: String): RestoreResponse {
    var derived: ByteArray? = null
    return try {
      val parameters = http.request(origin, "/v1/lan-recovery/parameters", "GET", auth.asBasic())
      if (parameters.status == 404) return RestoreResponse.Missing
      if (parameters.status != 200) throw IOException("LAN recovery parameters HTTP ${parameters.status}")
      requireFormat(parameters.body)
      if (parameters.body.getInt("triesRemaining") == 0) return RestoreResponse.PinMismatch(0)
      val revision = parameters.body.getString("revision")
      val salt = decoded(parameters.body.getString("salt"), 16)
      val keys = LanRecoveryCrypto.derive(pin, salt)
      derived = keys
      val response = http.request(
        origin, "/v1/lan-recovery/restore", "POST", auth.asBasic(),
        JSONObject().put("revision", revision).put("verifier", encoded(LanRecoveryCrypto.verifier(keys)))
      )
      when (response.status) {
        403, 423 -> RestoreResponse.PinMismatch(response.body.optInt("triesRemaining", 0).coerceIn(0, 10))
        404 -> RestoreResponse.Missing
        200 -> {
          requireFormat(response.body)
          require(response.body.getString("revision") == revision)
          require(MessageDigest.isEqual(decoded(response.body.getString("salt"), 16), salt))
          val master = LanRecoveryCrypto.decrypt(
            decoded(response.body.getString("ciphertext"), 48), keys,
            decoded(response.body.getString("nonce"), 12), auth.username(), revision
          )
          try {
            RestoreResponse.Success(MasterKey(master.copyOf()), auth)
          } finally {
            Arrays.fill(master, 0)
          }
        }
        else -> RestoreResponse.ApplicationError(IOException("LAN recovery restore HTTP ${response.status}"))
      }
    } catch (e: IOException) {
      RestoreResponse.NetworkError(e)
    } catch (e: Exception) {
      RestoreResponse.ApplicationError(e)
    } finally {
      derived?.let { Arrays.fill(it, 0) }
    }
  }

  private inner class Session(private val pin: String, private val master: MasterKey, restored: JSONObject? = null) : PinChangeSession {
    private val requestId = restored?.optString("requestId")?.takeIf { runCatching { UUID.fromString(it) }.isSuccess }
      ?: UUID.randomUUID().toString()
    private var payload: JSONObject? = restored?.optJSONObject("payload")
    private var subject: String? = restored?.optString("subject")?.takeIf { it.isNotBlank() }
    private var preparationError: Exception? = null

    private fun prepare(auth: AuthCredentials) {
      if (payload != null) {
        require(subject == auth.username()) { "LAN recovery identity changed" }
        return
      }
      val current = http.request(origin, "/v1/lan-recovery/parameters", "GET", auth.asBasic())
      val previous = when (current.status) {
        404 -> "absent"
        200 -> {
          requireFormat(current.body)
          current.body.getString("revision")
        }
        else -> throw IOException("LAN recovery parameters HTTP ${current.status}")
      }
      val salt = ByteArray(16).also(SecureRandom()::nextBytes)
      val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
      val keys = LanRecoveryCrypto.derive(pin, salt)
      try {
        payload = JSONObject()
          .put("format", 1).put("kdf", LanRecoveryCrypto.KDF).put("iterations", LanRecoveryCrypto.ITERATIONS)
          .put("requestId", requestId).put("expectedRevision", previous)
          .put("salt", encoded(salt)).put("nonce", encoded(nonce))
          .put("ciphertext", encoded(LanRecoveryCrypto.encrypt(master.serialize(), keys, nonce, auth.username(), requestId)))
          .put("verifier", encoded(LanRecoveryCrypto.verifier(keys)))
        subject = auth.username()
      } finally {
        Arrays.fill(keys, 0)
      }
    }

    override fun serialize(): String {
      preparationError = null
      try {
        prepare(authorization())
      } catch (e: Exception) {
        // A job persists its state before execute(). If preparation failed,
        // execute must not write an envelope absent from the persisted state.
        preparationError = e
      }
      return JSONObject().put("format", 1).put("requestId", requestId)
        .put("intent", intent(pin, master)).put("subject", subject)
        .put("payload", payload).toString()
    }

    override fun execute(): BackupResponse {
      preparationError?.let { error ->
        return if (error is IOException) BackupResponse.NetworkError(error) else BackupResponse.ApplicationError(error)
      }
      return try {
        val auth = authorization()
        prepare(auth)
        val response = http.request(origin, "/v1/lan-recovery/backup", "PUT", auth.asBasic(), requireNotNull(payload))
        when (response.status) {
          200 -> {
            require(response.body.getInt("format") == 1 && response.body.getString("revision") == requestId)
            BackupResponse.Success(master, auth, svrVersion)
          }
          409 -> BackupResponse.ServerRejected
          else -> BackupResponse.ApplicationError(IOException("LAN recovery backup HTTP ${response.status}"))
        }
      } catch (e: IOException) {
        BackupResponse.NetworkError(e)
      } catch (e: Exception) {
        BackupResponse.ApplicationError(e)
      }
    }
  }

  private fun intent(pin: String, master: MasterKey): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("signal-lan-recovery-intent-v1\u0000".toByteArray(Charsets.UTF_8))
    digest.update(pin.toByteArray(Charsets.UTF_8))
    digest.update(0.toByte())
    digest.update(master.serialize())
    return encoded(digest.digest())
  }

  private fun requireFormat(value: JSONObject) {
    require(value.getInt("format") == 1 && value.getString("kdf") == LanRecoveryCrypto.KDF && value.getInt("iterations") == LanRecoveryCrypto.ITERATIONS) {
      "Unsupported LAN recovery format"
    }
  }

  private fun encoded(value: ByteArray): String = Base64.encodeToString(value, Base64.NO_WRAP)

  private fun decoded(value: String, size: Int): ByteArray {
    require(value.length <= size * 2 + 16)
    return Base64.decode(value, Base64.NO_WRAP).also { require(it.size == size) }
  }

  override fun toString(): String = "SOFTWARE_LAN::v1"
}
