package org.thoughtcrime.securesms.registration.localauth

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import org.thoughtcrime.securesms.PassphraseRequiredActivity
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.util.DynamicNoActionBarTheme

/**
 * LAN-only deployment settings. The JSON is editable as one versioned document so operators can
 * import a configuration exported from their deployment tooling without rebuilding the APK.
 *
 * Settings are persisted locally and are loaded by SignalServiceNetworkAccess at process start;
 * restart Signal after saving them to rebuild the active network clients.
 */
class LocalNetworkSettingsActivity : PassphraseRequiredActivity() {
  private val dynamicTheme = DynamicNoActionBarTheme()
  private lateinit var configEditor: EditText

  override fun onCreate(savedInstanceState: Bundle?, ready: Boolean) {
    super.onCreate(savedInstanceState, ready)
    if (!ready) return
    dynamicTheme.onCreate(this)

    title = "Local server and device"
    val density = resources.displayMetrics.density
    fun dp(value: Int): Int = (value * density).toInt()
    fun text(value: String, size: Float = 14f): TextView = TextView(this).apply {
      this.text = value
      textSize = size
      setPadding(0, dp(8), 0, dp(8))
    }

    val content = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(20), dp(12), dp(20), dp(24))
      layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }
    content.addView(text("Local network configuration", 22f))
    content.addView(text(
      "Edit server-config.json below. All service addresses are validated before saving. " +
        "HTTPS/WSS and certificate validation are mandatory; SMS and cleartext traffic are disabled."
    ))

    configEditor = EditText(this).apply {
      inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
        InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
      gravity = Gravity.TOP or Gravity.START
      setTextIsSelectable(true)
      minLines = 18
      maxLines = 28
      setText(LocalServerConfigStore.readRawJson(this@LocalNetworkSettingsActivity))
      setPadding(dp(12), dp(12), dp(12), dp(12))
      layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(420)).apply {
        topMargin = dp(8)
        bottomMargin = dp(12)
      }
    }
    content.addView(configEditor)

    content.addView(button("Save and validate configuration") {
      try {
        LocalServerConfigStore.saveRawJson(this, configEditor.text.toString())
        Toast.makeText(this, "Configuration saved. Restart Signal to apply all endpoint changes.", Toast.LENGTH_LONG).show()
      } catch (e: Exception) {
        Toast.makeText(this, "Configuration not saved: ${e.message ?: "invalid JSON"}", Toast.LENGTH_LONG).show()
      }
    })

    content.addView(button("Copy current configuration JSON") {
      copyToClipboard("server-config.json", configEditor.text.toString())
      Toast.makeText(this, "Configuration JSON copied.", Toast.LENGTH_SHORT).show()
    })

    content.addView(button("Restore packaged LAN template") {
      LocalServerConfigStore.reset(this)
      configEditor.setText(LocalServerConfigStore.readRawJson(this))
      Toast.makeText(this, "Packaged LAN template restored. Restart Signal to apply it.", Toast.LENGTH_LONG).show()
    })

    content.addView(text("Enroll this Android device", 18f))
    content.addView(text(
      "Copy this JSON and provide it to the LAN administrator. The public key may be registered in the dashboard; " +
        "the private key stays inside Android Keystore and is never exported."
    ))
    content.addView(button("Copy device enrollment information") {
      try {
        val identity = LocalDeviceKeyManager.getOrCreateIdentity(this)
        val enrollment = JSONObject()
          .put("phoneNumber", SignalStore.account.e164 ?: "")
          .put("androidId", identity.androidId)
          .put("publicKey", identity.publicKeyBase64)
          .put("displayName", android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL)
          .toString(2)
        copyToClipboard("Signal device enrollment", enrollment)
        Toast.makeText(this, "Enrollment information copied. Send it only to your LAN administrator.", Toast.LENGTH_LONG).show()
      } catch (e: Exception) {
        Toast.makeText(this, "Could not access Android Keystore: ${e.message}", Toast.LENGTH_LONG).show()
      }
    })

    content.addView(text(
      "Important: the app loads network clients at process startup. After changing server endpoints, fully close and reopen Signal. " +
        "The server certificate must be trusted by Signal's configured service trust store."
    ))

    setContentView(ScrollView(this).apply {
      isFillViewport = true
      addView(content)
    })
  }

  override fun onResume() {
    super.onResume()
    dynamicTheme.onResume(this)
  }

  private fun button(label: String, action: () -> Unit): Button {
    return Button(this).apply {
      text = label
      isAllCaps = false
      setOnClickListener { action() }
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
      ).apply {
        bottomMargin = (8 * resources.displayMetrics.density).toInt()
      }
    }
  }

  private fun copyToClipboard(label: String, value: String) {
    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
  }
}
