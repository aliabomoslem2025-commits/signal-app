package org.thoughtcrime.securesms.registration.local

import android.content.Context
import org.json.JSONObject

/**
 * Runtime configuration for the private Signal deployment.
 *
 * Asset defaults can be overridden by an administrator-imported JSON file saved in app-private preferences.
 * This class never disables TLS certificate validation and rejects cleartext non-loopback endpoints.
 */
class LocalServerConfig private constructor(
  private val context: Context,
  private val defaults: JSONObject
) {
  companion object {
    private const val PREFS = "local_server_configuration"
    private const val KEY_CONFIG = "config_json"

    fun load(context: Context): LocalServerConfig {
      val appContext = context.applicationContext
      val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      val configured = prefs.getString(KEY_CONFIG, null)
      val source = configured ?: appContext.assets.open("server-config.json").bufferedReader().use { it.readText() }
      return LocalServerConfig(appContext, JSONObject(source))
    }
  }

  val localAuthOnly: Boolean
    get() = defaults.optBoolean("localAuthOnly", true)

  val localAuthApiUrl: String
    get() = normalizedEndpoint(defaults.optString("localAuthApiUrl"))

  fun endpoint(module: String): String {
    val services = defaults.optJSONObject("services") ?: JSONObject()
    return normalizedEndpoint(services.optString(module))
  }

  fun saveEndpoint(module: String, value: String) {
    val normalized = normalizedEndpoint(value)
    val services = defaults.optJSONObject("services") ?: JSONObject().also {
      defaults.put("services", it)
    }
    services.put(module, normalized)
    persist()
  }

  fun saveLocalAuthApiUrl(value: String) {
    defaults.put("localAuthApiUrl", normalizedEndpoint(value))
    persist()
  }

  fun exportJson(): String = defaults.toString(2)

  fun importJson(json: String) {
    val parsed = JSONObject(json)
    require(parsed.optInt("schemaVersion") == 1) { "Unsupported server-config.json schemaVersion" }
    val security = parsed.optJSONObject("security") ?: JSONObject()
    require(security.optBoolean("requireHttps", true)) {
      "LAN deployments must require HTTPS"
    }
    require(security.optBoolean("validateCertificates", true)) {
      "Certificate validation cannot be disabled"
    }
    normalizedEndpoint(parsed.optString("localAuthApiUrl"))
    val services = parsed.optJSONObject("services") ?: JSONObject()
    val names = listOf("signal", "storage", "cdn0", "cdn2", "cdn3", "cdsi", "svr2", "svrb", "attachments", "sfu")
    names.forEach { name ->
      val value = services.optString(name)
      if (value.isNotBlank()) normalizedEndpoint(value)
    }
    defaults.keys().asSequence().toList().forEach(defaults::remove)
    parsed.keys().forEach { key -> defaults.put(key, parsed.get(key)) }
    persist()
  }

  private fun persist() {
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .edit()
      .putString(KEY_CONFIG, defaults.toString())
      .apply()
  }

  private fun normalizedEndpoint(value: String): String {
    val trimmed = value.trim().trimEnd('/')
    require(trimmed.isNotBlank()) { "Server endpoint is empty" }
    val uri = java.net.URI(trimmed)
    val scheme = uri.scheme?.lowercase()
    val host = uri.host
    val loopback = host == "localhost" || host == "127.0.0.1" || host == "::1"
    require(scheme == "https" || (scheme == "http" && loopback)) {
      "Server endpoints must use HTTPS (HTTP is allowed only for loopback development)"
    }
    require(host != null && uri.userInfo == null && uri.query == null && uri.fragment == null) {
      "Invalid server endpoint"
    }
    return trimmed
  }
}
