package org.thoughtcrime.securesms.contacts.sync

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.signal.core.models.ServiceId.PNI
import org.signal.network.NetworkResult
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.registration.local.LanHttpClient
import org.thoughtcrime.securesms.registration.local.LocalServerConfig
import org.whispersystems.signalservice.api.cds.CdsiV2Service
import org.whispersystems.signalservice.api.push.exceptions.CdsiResourceExhaustedException
import java.io.IOException
import java.util.Optional
import java.util.UUID

/** LAN administrator trust replaces enclave privacy; there is no public fallback. */
object LanContactDiscovery {
  private val http by lazy { LanHttpClient(AppDependencies.application) }

  fun lookup(numbers: Set<String>, timeoutMs: Long? = null): NetworkResult<CdsiV2Service.Response> {
    return try {
      val account = SignalStore.account
      if (!account.isRegistered) throw IOException("LAN discovery requires registration")
      val password = account.servicePassword ?: throw IOException("LAN service credentials unavailable")
      val username = account.requireAci().toString() + if (account.deviceId == 1) "" else ".${account.deviceId}"
      val authorization = "Basic " + Base64.encodeToString("$username:$password".toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
      val origin = LocalServerConfig.load(AppDependencies.application).signalApiUrl
      val results = linkedMapOf<String, CdsiV2Service.ResponseItem>()
      for (batch in numbers.sorted().chunked(256)) {
        val response = http.request(origin, "/v1/lan/directory", "POST", authorization,
          JSONObject().put("numbers", JSONArray(batch)), (timeoutMs ?: 10_000L).coerceIn(1000, 30_000).toInt())
        if (response.status == 429) {
          return NetworkResult.StatusCodeError(CdsiResourceExhaustedException(response.retryAfterSeconds ?: 60))
        }
        if (response.status != 200) throw IOException("LAN discovery HTTP ${response.status}")
        require(response.body.getInt("format") == 1)
        val found = response.body.getJSONObject("results")
        for (number in found.keys()) {
          require(number in batch) { "Unexpected LAN directory entry" }
          val pni = PNI.from(UUID.fromString(found.getJSONObject(number).getString("pni")))
          results[number] = CdsiV2Service.ResponseItem(pni, Optional.empty())
        }
      }
      NetworkResult.Success(CdsiV2Service.Response(results, numbers.size))
    } catch (e: IOException) {
      NetworkResult.NetworkError(e)
    } catch (e: Exception) {
      NetworkResult.ApplicationError(e)
    }
  }
}
