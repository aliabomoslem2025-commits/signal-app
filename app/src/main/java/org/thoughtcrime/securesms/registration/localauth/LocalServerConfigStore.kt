/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.thoughtcrime.securesms.registration.localauth

import android.content.Context
import android.net.Uri
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateFactory
import org.json.JSONObject

/**
 * Runtime endpoint configuration for a privately deployed Signal server.
 *
 * The admin bearer token is deliberately not part of this configuration. It belongs only on the
 * server and must never be packaged in the APK.
 */
data class LocalServerConfig(
  val apiBaseUrl: String,
  val websocketBaseUrl: String,
  val trustedCaPem: String,
  val cdn0: String,
  val cdn2: String,
  val cdn3: String,
  val storage: String,
  val cdsi: String,
  val svr2: String,
  val svrb: String,
  val attachments: String,
  val sfu: String,
  val turn: String,
  val smsEnabled: Boolean,
  val allowCleartext: Boolean,
  val validateCertificates: Boolean
) {
  fun validate(): LocalServerConfig {
    require(isHttpEndpoint(apiBaseUrl)) { "apiBaseUrl must use HTTPS" }
    require(isWebSocketEndpoint(websocketBaseUrl)) { "websocketBaseUrl must use WSS" }
    require(isHttpEndpoint(cdn0)) { "cdn0 must use HTTPS" }
    require(isHttpEndpoint(cdn2)) { "cdn2 must use HTTPS" }
    require(isHttpEndpoint(cdn3)) { "cdn3 must use HTTPS" }
    require(isHttpEndpoint(storage)) { "storage must use HTTPS" }
    require(isHttpEndpoint(cdsi)) { "cdsi must use HTTPS" }
    require(isHttpEndpoint(svr2)) { "svr2 must use HTTPS" }
    require(isHttpEndpoint(svrb)) { "svrb must use HTTPS" }
    require(isHttpEndpoint(attachments)) { "attachments must use HTTPS" }
    require(isHttpEndpoint(sfu)) { "sfu must use HTTPS" }
    require(turn.startsWith("turn:") || turn.startsWith("turns:")) { "turn must use TURN/TURNS" }
    require(!allowCleartext) { "Cleartext traffic is not supported for local authentication" }
    require(validateCertificates) { "TLS certificate validation cannot be disabled" }
    require(!smsEnabled) { "SMS verification is disabled in LOCAL_DEVICE_AUTH mode" }
    require(trustedCaPem.length <= 32 * 1024) { "trustedCaPem exceeds 32 KiB." }
    if (trustedCaPem.isNotBlank()) {
      val certificates = CertificateFactory.getInstance("X.509").generateCertificates(
        ByteArrayInputStream(trustedCaPem.toByteArray(StandardCharsets.US_ASCII))
      )
      require(certificates.isNotEmpty()) { "trustedCaPem must contain at least one X.509 certificate." }
    }
    return this
  }

  private fun isHttpEndpoint(value: String): Boolean {
    val uri = Uri.parse(value)
    return uri.scheme == "https" && !uri.host.isNullOrBlank()
  }

  private fun isWebSocketEndpoint(value: String): Boolean {
    val uri = Uri.parse(value)
    return uri.scheme == "wss" && !uri.host.isNullOrBlank()
  }
}

object LocalServerConfigStore {
  private const val PREFS_NAME = "local_server_config"
  private const val CONFIG_KEY = "config_json"

  fun load(context: Context): LocalServerConfig {
    return parse(JSONObject(readRawJson(context))).validate()
  }

  /** Returns the editable JSON currently in use, falling back to the packaged LAN template. */
  fun readRawJson(context: Context): String {
    val preferences = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    return preferences.getString(CONFIG_KEY, null)
      ?: context.applicationContext.assets.open("server-config.json").bufferedReader().use { it.readText() }
  }

  /**
   * Validates the complete configuration before persisting it. Invalid or insecure settings never replace
   * the last-known-good configuration.
   */
  fun saveRawJson(context: Context, rawJson: String) {
    require(rawJson.length <= 64 * 1024) { "Configuration file is too large (maximum 64 KiB)." }
    val root = JSONObject(rawJson)
    require(root.optInt("schemaVersion", -1) == 1) { "Unsupported server-config.json schemaVersion." }
    parse(root).validate()
    context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(CONFIG_KEY, root.toString(2))
      .apply()
  }

  fun save(context: Context, config: LocalServerConfig) {
    val validated = config.validate()
    val json = JSONObject().apply {
      put("schemaVersion", 1)
      put("environment", "LAN")
      put("apiBaseUrl", validated.apiBaseUrl)
      put("websocketBaseUrl", validated.websocketBaseUrl)
      put("trustedCaPem", validated.trustedCaPem)
      put("modules", JSONObject().apply {
        put("cdn0", validated.cdn0)
        put("cdn2", validated.cdn2)
        put("cdn3", validated.cdn3)
        put("storage", validated.storage)
        put("cdsi", validated.cdsi)
        put("svr2", validated.svr2)
        put("svrb", validated.svrb)
        put("attachments", validated.attachments)
        put("sfu", validated.sfu)
        put("turn", validated.turn)
      })
      put("authentication", JSONObject().apply {
        put("mode", "LOCAL_DEVICE_AUTH")
        put("smsEnabled", validated.smsEnabled)
      })
      put("security", JSONObject().apply {
        put("allowCleartext", validated.allowCleartext)
        put("validateCertificates", validated.validateCertificates)
      })
    }
    context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(CONFIG_KEY, json.toString())
      .apply()
  }

  fun reset(context: Context) {
    context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .remove(CONFIG_KEY)
      .apply()
  }

  private fun parse(root: JSONObject): LocalServerConfig {
    val modules = root.optJSONObject("modules") ?: JSONObject()
    val authentication = root.optJSONObject("authentication") ?: JSONObject()
    val security = root.optJSONObject("security") ?: JSONObject()
    return LocalServerConfig(
      apiBaseUrl = root.optString("apiBaseUrl", ""),
      websocketBaseUrl = root.optString("websocketBaseUrl", ""),
      trustedCaPem = root.optString("trustedCaPem", ""),
      cdn0 = modules.optString("cdn0", ""),
      cdn2 = modules.optString("cdn2", ""),
      cdn3 = modules.optString("cdn3", ""),
      storage = modules.optString("storage", ""),
      cdsi = modules.optString("cdsi", ""),
      svr2 = modules.optString("svr2", ""),
      svrb = modules.optString("svrb", ""),
      attachments = modules.optString("attachments", ""),
      sfu = modules.optString("sfu", ""),
      turn = modules.optString("turn", ""),
      smsEnabled = authentication.optBoolean("smsEnabled", false),
      allowCleartext = security.optBoolean("allowCleartext", false),
      validateCertificates = security.optBoolean("validateCertificates", true)
    )
  }
}
