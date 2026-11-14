package org.thoughtcrime.securesms.registration.local

import android.content.Context
import org.json.JSONObject
import org.webrtc.PeerConnection

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

  val trustedCaPem: String
    get() = defaults.optString("trustedCaPem").trim()

  fun endpoint(module: String): String {
    val services = defaults.optJSONObject("services") ?: JSONObject()
    val value = services.optString(module)
    return if (module == "turn") normalizedTurnEndpoint(value) else normalizedEndpoint(value)
  }

  /**
   * Optional static TURN override for isolated LANs. When credentials are omitted, the app
   * continues to request short-lived TURN credentials from the configured Signal Calling API.
   */
  fun configuredTurnServers(): List<PeerConnection.IceServer> {
    val services = defaults.optJSONObject("services") ?: JSONObject()
    val url = services.optString("turn").takeIf { it.isNotBlank() } ?: return emptyList()
    val username = services.optString("turnUsername").trim()
    val credential = services.optString("turnCredential").trim()
    if (username.isBlank() || credential.isBlank()) return emptyList()

    return listOf(
      PeerConnection.IceServer.builder(normalizedTurnEndpoint(url))
        .setUsername(username)
        .setPassword(credential)
        .createIceServer()
    )
  }

  fun saveEndpoint(module: String, value: String) {
    val normalized = if (module == "turn") normalizedTurnEndpoint(value) else normalizedEndpoint(value)
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

  fun saveTrustedCaPem(pem: String) {
    require(pem.contains("-----BEGIN CERTIFICATE-----") && pem.contains("-----END CERTIFICATE-----")) {
      "A PEM-encoded X.509 CA certificate is required"
    }
    defaults.put("trustedCaPem", pem.trim())
    persist()
  }

  fun exportJson(): String = defaults.toString(2)

  fun importJson(json: String) {
    val parsed = JSONObject(json)
    require(parsed.optInt("schemaVersion") == 1) { "Unsupported server-config.json schemaVersion" }
    require(parsed.optBoolean("localAuthOnly", true)) {
      "This LAN build requires localAuthOnly=true; SMS and public Signal registration are disabled"
    }
    val security = parsed.optJSONObject("security") ?: JSONObject()
    require(security.optBoolean("requireHttps", true)) {
      "LAN deployments must require HTTPS"
    }
    require(security.optBoolean("validateCertificates", true)) {
      "Certificate validation cannot be disabled"
    }
    normalizedEndpoint(parsed.optString("localAuthApiUrl"))
    if (parsed.optBoolean("localAuthOnly", true)) {
      val caPem = parsed.optString("trustedCaPem")
      require(caPem.contains("-----BEGIN CERTIFICATE-----") && caPem.contains("-----END CERTIFICATE-----")) {
        "Local LAN mode requires trustedCaPem with a private CA certificate"
      }
    }
    val services = parsed.optJSONObject("services") ?: JSONObject()
    val names = listOf("signal", "storage", "cdn0", "cdn2", "cdn3", "cdsi", "svr2", "svrb", "attachments", "sfu")
    names.forEach { name ->
      val value = services.optString(name)
      if (value.isNotBlank()) normalizedEndpoint(value)
    }
    services.optString("turn").takeIf { it.isNotBlank() }?.let(::normalizedTurnEndpoint)
    val turnUsername = services.optString("turnUsername").trim()
    val turnCredential = services.optString("turnCredential").trim()
    require(turnUsername.isBlank() == turnCredential.isBlank()) {
      "A static TURN username and credential must be provided together"
    }
    if (turnUsername.isNotBlank()) {
      normalizedTurnEndpoint(services.optString("turn"))
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

  private fun normalizedTurnEndpoint(value: String): String {
    val trimmed = value.trim()
    val uri = java.net.URI(trimmed)
    val scheme = uri.scheme?.lowercase()
    require(scheme == "turn" || scheme == "turns") { "TURN endpoint must use turn: or turns:" }
    require(uri.host != null && uri.userInfo == null && uri.query == null && uri.fragment == null) {
      "Invalid TURN endpoint"
    }
    return trimmed
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
