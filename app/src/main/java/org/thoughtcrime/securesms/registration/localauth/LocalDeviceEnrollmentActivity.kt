package org.thoughtcrime.securesms.registration.localauth

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject

/**
 * Enrollment bootstrap available before the account is registered.
 *
 * The administrator uses the copied phone/Android-ID/public-key tuple to pre-authorize this
 * device in the LAN dashboard. The private key remains in Android Keystore and is never exported.
 */
class LocalDeviceEnrollmentActivity : Activity() {
  companion object {
    const val EXTRA_PHONE_NUMBER = "org.thoughtcrime.securesms.localauth.PHONE_NUMBER"
    private const val E164_PATTERN = "^\\+[1-9][0-9]{7,14}$"
  }

  private lateinit var phoneNumberInput: EditText
  private lateinit var enrollmentPreview: TextView
  private var enrollmentJson: String? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    title = "Enroll this Android device"

    val density = resources.displayMetrics.density
    fun dp(value: Int): Int = (value * density).toInt()
    fun label(value: String, size: Float = 14f) = TextView(this).apply {
      text = value
      textSize = size
      setPadding(0, dp(8), 0, dp(8))
    }
    fun button(value: String, action: () -> Unit) = Button(this).apply {
      text = value
      isAllCaps = false
      setOnClickListener { action() }
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
      ).apply { bottomMargin = dp(8) }
    }

    val content = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(24), dp(20), dp(24), dp(24))
    }
    content.addView(label("Register this device with your LAN administrator", 21f))
    content.addView(label(
      "Enter the same phone number that the administrator has assigned to you. " +
        "Copy the enrollment record and send it to the administrator through a trusted channel. " +
        "The private signing key never leaves Android Keystore."
    ))

    phoneNumberInput = EditText(this).apply {
      inputType = InputType.TYPE_CLASS_PHONE
      hint = "Phone number in E.164 format, e.g. +491234567890"
      setSingleLine(true)
      setText(intent.getStringExtra(EXTRA_PHONE_NUMBER).orEmpty())
    }
    content.addView(phoneNumberInput)

    content.addView(button("Generate enrollment information") {
      generateEnrollment()
    })

    enrollmentPreview = label("Enrollment information has not been generated.")
    enrollmentPreview.textIsSelectable = true
    content.addView(enrollmentPreview)

    content.addView(button("Copy enrollment JSON") {
      val value = enrollmentJson
      if (value == null) {
        Toast.makeText(this, "Generate enrollment information first.", Toast.LENGTH_SHORT).show()
      } else {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Signal LAN device enrollment", value))
        Toast.makeText(this, "Enrollment JSON copied.", Toast.LENGTH_LONG).show()
      }
    })

    content.addView(label(
      "Administrator action: in Signal LAN Dashboard, authorize the phone number, Android ID, " +
        "public key and device name. Do not ask the user for the private key."
    ))

    setContentView(ScrollView(this).apply {
      isFillViewport = true
      addView(content)
    })

    if (phoneNumberInput.text?.isNotBlank() == true) {
      generateEnrollment()
    }
  }

  private fun generateEnrollment() {
    val phoneNumber = phoneNumberInput.text?.toString()?.trim().orEmpty()
    if (!phoneNumber.matches(Regex(E164_PATTERN))) {
      Toast.makeText(this, "Enter a valid E.164 phone number.", Toast.LENGTH_LONG).show()
      return
    }

    try {
      val identity = LocalDeviceKeyManager.getOrCreateIdentity(this)
      val value = JSONObject()
        .put("phoneNumber", phoneNumber)
        .put("androidId", identity.androidId)
        .put("publicKey", identity.publicKeyBase64)
        .put("displayName", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".trim())
        .toString(2)

      enrollmentJson = value
      enrollmentPreview.text = value
    } catch (e: Exception) {
      enrollmentJson = null
      enrollmentPreview.text = "Could not create device identity: ${e.message ?: "Android Keystore error"}"
      Toast.makeText(this, enrollmentPreview.text, Toast.LENGTH_LONG).show()
    }
  }
}
