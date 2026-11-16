package org.thoughtcrime.securesms.push

import java.net.URI
import java.util.Locale

/**
 * Only explicitly configured HTTPS destinations may be reached by the
 * OkHttp Signal service transport. This also covers the redirect network
 * interceptor path. Separate libsignal native/third-party HTTP clients must
 * be assessed independently before certifying zero public network access.
 */
internal class LanDestinationPolicy(configuredUrls: Collection<String>) {
  private val authorities: Set<Pair<String, Int>> = configuredUrls.map { rawUrl ->
    val uri = URI(rawUrl)
    require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()) {
      "LAN endpoints must be valid HTTPS URLs"
    }
    require(uri.rawUserInfo == null && uri.rawFragment == null && uri.rawQuery == null) {
      "LAN endpoints must not contain credentials, fragments or queries"
    }
    val port = if (uri.port == -1) 443 else uri.port
    require(port in 1..65535) { "LAN endpoint port out of range" }
    uri.host.lowercase(Locale.ROOT) to port
  }.toSet()

  fun permits(scheme: String, hostname: String, port: Int): Boolean =
    scheme.equals("https", ignoreCase = true) && (hostname.lowercase(Locale.ROOT) to port) in authorities
}
