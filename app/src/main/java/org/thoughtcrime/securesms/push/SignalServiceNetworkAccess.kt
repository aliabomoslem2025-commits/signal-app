package org.thoughtcrime.securesms.push

import android.content.Context
import okhttp3.Dns
import okhttp3.Interceptor
import org.signal.core.util.Base64
import org.signal.core.util.logging.Log
import org.signal.network.config.SignalCdnUrl
import org.signal.network.config.SignalCdsiUrl
import org.signal.network.config.SignalServiceConfiguration
import org.signal.network.config.SignalServiceUrl
import org.signal.network.config.SignalStorageUrl
import org.signal.network.config.SignalSvr2Url
import org.signal.network.config.TrustStore
import org.signal.libsignal.zkgroup.GenericServerPublicParams
import org.signal.libsignal.zkgroup.ServerPublicParams
import org.thoughtcrime.securesms.BuildConfig
import org.thoughtcrime.securesms.net.DeprecatedClientPreventionInterceptor
import org.thoughtcrime.securesms.net.DeviceTransferBlockingInterceptor
import org.thoughtcrime.securesms.net.RemoteDeprecationDetectorInterceptor
import org.thoughtcrime.securesms.net.StandardUserAgentInterceptor
import org.thoughtcrime.securesms.net.StorageServiceSizeLoggingInterceptor
import org.thoughtcrime.securesms.registration.local.LocalServerConfig
import java.io.IOException
import java.util.Optional

/**
 * Self-hosted LAN-only transport.
 *
 * There are no public Signal URLs, public DNS resolvers, censorship
 * domain-fronting alternatives, or transparent public-server fallbacks.
 * A missing LAN CA or an invalid hostname is an explicit connection failure.
 */
class SignalServiceNetworkAccess(context: Context) {
  companion object {
    private val TAG = Log.tag(SignalServiceNetworkAccess::class.java)

    /** Only the device/admin's trusted LAN resolver may resolve *.lan hosts. */
    @JvmField
    val DNS: Dns = Dns.SYSTEM
  }

  private val endpoints: LocalServerConfig = LocalServerConfig.load(context)
  private val lanTrust: TrustStore = LocalServerTrustStore(context)

  private val networkInterceptors: List<Interceptor> = listOf(
    StandardUserAgentInterceptor(),
    StorageServiceSizeLoggingInterceptor(),
    RemoteDeprecationDetectorInterceptor(this::getConfiguration),
    DeprecatedClientPreventionInterceptor(),
    DeviceTransferBlockingInterceptor.getInstance()
  )

  private val zkGroupServerPublicParams: ByteArray = decodePublicParams("zkgroup", BuildConfig.ZKGROUP_SERVER_PUBLIC_PARAMS)
  private val genericServerPublicParams: ByteArray = decodePublicParams("generic", BuildConfig.GENERIC_SERVER_PUBLIC_PARAMS)
  private val backupServerPublicParams: ByteArray = decodePublicParams("backup", BuildConfig.BACKUP_SERVER_PUBLIC_PARAMS)

  private fun decodePublicParams(kind: String, data: String): ByteArray {
    if (data.isBlank()) {
      // Do not substitute Signal production cryptographic roots.
      throw IllegalStateException("Local Signal $kind server public parameters are missing")
    }

    val decoded = try {
      Base64.decode(data)
    } catch (e: IOException) {
      throw IllegalStateException("Invalid local $kind public parameters: malformed Base64", e)
    }

    try {
      when (kind) {
        "zkgroup" -> ServerPublicParams(decoded)
        "generic", "backup" -> GenericServerPublicParams(decoded)
        else -> throw IllegalArgumentException("Unknown local server parameter kind: $kind")
      }
    } catch (e: Exception) {
      throw IllegalStateException(
        "Local Signal $kind server public parameters are not valid for this libsignal build",
        e
      )
    }

    return decoded
  }

  val uncensoredConfiguration: SignalServiceConfiguration = SignalServiceConfiguration(
    signalServiceUrls = arrayOf(SignalServiceUrl(endpoints.signalApiUrl, lanTrust)),
    signalCdnUrlMap = mapOf(
      0 to arrayOf(SignalCdnUrl(endpoints.cdn0Url, lanTrust)),
      2 to arrayOf(SignalCdnUrl(endpoints.cdn2Url, lanTrust)),
      3 to arrayOf(SignalCdnUrl(endpoints.cdn3Url, lanTrust))
    ),
    signalStorageUrls = arrayOf(SignalStorageUrl(endpoints.storageUrl, lanTrust)),
    signalCdsiUrls = arrayOf(SignalCdsiUrl(endpoints.cdsiUrl, lanTrust)),
    signalSvr2Urls = arrayOf(SignalSvr2Url(endpoints.svr2Url, lanTrust)),
    networkInterceptors = networkInterceptors,
    dns = Optional.of(DNS),
    signalProxy = Optional.empty(),
    zkGroupServerPublicParams = zkGroupServerPublicParams,
    genericServerPublicParams = genericServerPublicParams,
    backupServerPublicParams = backupServerPublicParams,
    censored = false
  )

  @Suppress("UNUSED_PARAMETER")
  fun getConfiguration(e164: String?): SignalServiceConfiguration = uncensoredConfiguration

  fun getConfiguration(): SignalServiceConfiguration = uncensoredConfiguration

  fun isCensored(): Boolean = false

  @Suppress("UNUSED_PARAMETER")
  fun isCensored(number: String?): Boolean = false

  @Suppress("UNUSED_PARAMETER")
  fun isCountryCodeCensoredByDefault(countryCode: Int): Boolean = false

  fun hasRecentDirectTransportFailure(): Boolean = false

  fun onNetworkChange() {
    Log.d(TAG, "LAN network changed; system DNS and TLS will reconnect normally")
  }
}
