package org.thoughtcrime.securesms.network.local

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.URI

/**
 * Runtime LAN endpoint configuration. The app deliberately defaults to LAN-only endpoints;
 * an absent or invalid file must never silently fall back to Signal's public infrastructure.
 */
data class LocalServerConfig(
  val localAuthEnabled: Boolean = true,
  val localAuthUrl: String = "https://auth.lan",
  val signalApiUrl: String = "https://messenger.lan",
  val websocketUrl: String = "wss://messenger.lan",
  val storageUrl: String = "https://storage.lan",
  val cdn0Url: String = "https://cdn0.lan",
  val cdn2Url: String = "https://cdn2.lan",
  val cdn3Url: String = "https://cdn3.lan",
  val cdsiUrl: String = "https://cdsi.lan",
  val svr2Url: String = "https://svr2.lan",
  val sfuUrl: String = "https://sfu.lan",
  val turnUrl: String = "turn:turn.lan:3478",
  val caCertificatePem: String = ""
) {
  fun toJson(): String = JSONObject().apply {
    put("schemaVersion", 1)
    put("environment", "LAN")
    put("authentication", JSONObject().apply {
      put("mode", "LOCAL_DEVICE_AUTH")
      put("enabled", localAuthEnabled)
      put("sms_enabled", false)
      put("device_verification", true)
    })
    put("server", JSONObject().apply {
      put("api", signalApiUrl)
      put("websocket", websocketUrl)
      put("localAuth", localAuthUrl)
    })
    put("modules", JSONObject().apply {
      put("storage", storageUrl)
      put("cdn0", cdn0Url)
      put("cdn2", cdn2Url)
      put("cdn3", cdn3Url)
      put("cdsi", cdsiUrl)
      put("svr2", svr2Url)
      put("calling", JSONObject().apply {
        put("sfu", sfuUrl)
        put("turn", turnUrl)
      })
    })
    put("security", JSONObject().apply {
      put("allow_cleartext", false)
      put("certificate_validation", true)
      put("ca_certificate_pem", caCertificatePem)
    })
  }.toString(2)

  companion object {
    fun fromJson(source: String): LocalServerConfig {
      val root = JSONObject(source)
      require(root.optInt("schemaVersion", -1) == 1) { "نسخه فایل تنظیمات پشتیبانی نمی‌شود." }
      val auth = root.optJSONObject("authentication") ?: JSONObject()
      val server = root.optJSONObject("server") ?: JSONObject()
      val modules = root.optJSONObject("modules") ?: JSONObject()
      val calling = modules.optJSONObject("calling") ?: JSONObject()
      val security = root.optJSONObject("security") ?: JSONObject()
      val config = LocalServerConfig(
        localAuthEnabled = auth.optBoolean("enabled", true),
        localAuthUrl = server.optString("localAuth", "https://auth.lan"),
        signalApiUrl = server.optString("api", "https://messenger.lan"),
        websocketUrl = server.optString("websocket", "wss://messenger.lan"),
        storageUrl = modules.optString("storage", "https://storage.lan"),
        cdn0Url = modules.optString("cdn0", "https://cdn0.lan"),
        cdn2Url = modules.optString("cdn2", "https://cdn2.lan"),
        cdn3Url = modules.optString("cdn3", "https://cdn3.lan"),
        cdsiUrl = modules.optString("cdsi", "https://cdsi.lan"),
        svr2Url = modules.optString("svr2", "https://svr2.lan"),
        sfuUrl = calling.optString("sfu", "https://sfu.lan"),
        turnUrl = calling.optString("turn", "turn:turn.lan:3478"),
        caCertificatePem = security.optString("ca_certificate_pem", "")
      )
      config.validate()
      return config
    }

    fun load(context: Context): LocalServerConfig {
      val file = File(context.applicationContext.filesDir, "server-config.json")
      if (!file.exists()) return LocalServerConfig()
      return fromJson(file.readText(Charsets.UTF_8))
    }

    fun save(context: Context, config: LocalServerConfig) {
      config.validate()
      val destination = File(context.applicationContext.filesDir, "server-config.json")
      val temporary = File(destination.parentFile, "server-config.json.tmp")
      temporary.writeText(config.toJson(), Charsets.UTF_8)
      if (!temporary.renameTo(destination)) {
        temporary.copyTo(destination, overwrite = true)
        temporary.delete()
      }
    }
  }

  fun validate() {
    require(localAuthEnabled) { "این نسخه فقط از احراز هویت محلی پشتیبانی می‌کند." }
    listOf(localAuthUrl, signalApiUrl, storageUrl, cdn0Url, cdn2Url, cdn3Url, cdsiUrl, svr2Url, sfuUrl).forEach {
      validateHttpsUrl(it)
    }
    require(websocketUrl.startsWith("wss://", ignoreCase = true)) { "آدرس WebSocket باید از WSS استفاده کند." }
    require(!turnUrl.startsWith("http://", ignoreCase = true)) { "آدرس TURN نامعتبر است." }
    require(caCertificatePem.contains("-----BEGIN CERTIFICATE-----") &&
      caCertificatePem.contains("-----END CERTIFICATE-----")) {
      "گواهی CA محلی (PEM) باید وارد شود؛ اعتبارسنجی TLS غیرفعال نمی‌شود."
    }
  }

  private fun validateHttpsUrl(value: String) {
    val uri = URI(value.trim())
    require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()) {
      "تمام آدرس‌های HTTP API باید HTTPS باشند: $value"
    }
    require(uri.userInfo == null && uri.query == null && uri.fragment == null) {
      "آدرس سرویس نباید حاوی اطلاعات ورود، query یا fragment باشد."
    }
  }
}

/** Stable facade shared by networking, registration, and the settings UI. */
object LocalServerConfigStore {
  fun load(context: Context): LocalServerConfig = LocalServerConfig.load(context)

  fun save(context: Context, config: LocalServerConfig) = LocalServerConfig.save(context, config)
}
