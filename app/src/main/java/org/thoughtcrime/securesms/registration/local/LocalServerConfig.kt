package org.thoughtcrime.securesms.registration.local

import android.content.Context
import org.json.JSONObject
import java.net.URI

/**
 * LAN release configuration. Edit app/src/main/assets/server-config.json
 * before compiling. No runtime fall back to production Signal endpoints.
 */
class LocalServerConfig private constructor(
  val signalApiUrl: String,
  val localAuthApiUrl: String,
  val ntfyBaseUrl: String,
  val cdn0Url: String,
  val cdn2Url: String,
  val cdn3Url: String,
  val storageUrl: String,
  val cdsiUrl: String,
  val svr2Url: String,
  val callingSfuUrl: String,
  val tusUrl: String,
  val trustedCaPem: String
) {
  val localAuthOnly: Boolean get() = true

  companion object {
    @Volatile private var cached: LocalServerConfig? = null

    fun load(context: Context): LocalServerConfig {
      cached?.let { return it }
      return synchronized(this) {
        cached ?: parse(context.assets.open("server-config.json").bufferedReader().use { it.readText() }).also { cached = it }
      }
    }

    internal fun parse(raw: String): LocalServerConfig {
      val json = JSONObject(raw)
      require(json.getString("mode") == "LOCAL_LAN" && json.getBoolean("localAuthOnly")) {
        "This build requires LAN-only device authentication"
      }
      val security = json.getJSONObject("security")
      require(security.getBoolean("requireHttps") && !security.getBoolean("allowCleartext") && security.getBoolean("validateCertificates")) {
        "TLS and certificate validation are mandatory"
      }
      val urls = json.getJSONObject("services")
      fun endpoint(name: String): String {
        val rawEndpoint = urls.getString(name).trim().trimEnd('/')
        val uri = URI(rawEndpoint)
        require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
          "LAN endpoint $name must be an absolute HTTPS URL without credentials"
        }
        return rawEndpoint
      }
      return LocalServerConfig(
        signalApiUrl = endpoint("signalApi"),
        localAuthApiUrl = endpoint("localAuthApi"),
        ntfyBaseUrl = endpoint("ntfy"),
        cdn0Url = endpoint("cdn0"),
        cdn2Url = endpoint("cdn2"),
        cdn3Url = endpoint("cdn3"),
        storageUrl = endpoint("storage"),
        cdsiUrl = endpoint("cdsi"),
        svr2Url = endpoint("svr2"),
        callingSfuUrl = endpoint("callingSfu"),
        tusUrl = endpoint("tus"),
        trustedCaPem = security.optString("trustedCaPem").trim()
      )
    }
  }
}
