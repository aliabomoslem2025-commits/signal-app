package org.thoughtcrime.securesms.registration.local

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * Available *before* registration. The administrator scans/copies the
 * Android ID and Keystore PUBLIC key to enroll one authorized handset.
 * No private key, admin secret or ntfy publisher token can be exported.
 */
class LocalServerSettingsActivity : Activity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val density = resources.displayMetrics.density
    val pad = (20 * density).toInt()
    val content = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(pad, pad, pad, pad)
    }
    fun label(text: String, size: Float = 16f) {
      content.addView(TextView(this).apply {
        this.text = text
        textSize = size
        setPadding(0, (8 * density).toInt(), 0, (8 * density).toInt())
      }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    label("Signal LAN — Device enrollment", 23f)
    label("Only an administrator-enrolled device can activate a phone number. Your private signing key never leaves Android Keystore.")
    val cfg = LocalServerConfig.load(this)
    label("Signal API: ${cfg.signalApiUrl}\nLocal authentication: ${cfg.localAuthApiUrl}\nntfy: ${cfg.ntfyBaseUrl}")
    label(if (cfg.trustedCaPem.contains("-----BEGIN CERTIFICATE-----")) "Private LAN CA: configured" else "Private LAN CA: NOT CONFIGURED")
    val info = TextView(this).apply {
      textSize = 12f
      setTextIsSelectable(true)
      setPadding(0, pad, 0, pad)
    }
    content.addView(Button(this).apply {
      text = "Copy device enrollment information"
      setOnClickListener {
        try {
          val data = LocalDeviceAuthClient(this@LocalServerSettingsActivity).enrollmentInformation().toString(2)
          info.text = data
          (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
            .setPrimaryClip(ClipData.newPlainText("Signal LAN device public enrollment", data))
          Toast.makeText(this@LocalServerSettingsActivity, "Public enrollment information copied", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
          Toast.makeText(this@LocalServerSettingsActivity, "Android Keystore enrollment unavailable", Toast.LENGTH_LONG).show()
        }
      }
    })
    content.addView(info)
    label("Important: Android ID alone does not prove SIM ownership. Approval requires the administrator, and physical SIM presence requires carrier/SMS validation separately.")
    setContentView(ScrollView(this).apply { addView(content) })
  }
}
