package org.thoughtcrime.securesms.registration.localauth

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
import org.thoughtcrime.securesms.PassphraseRequiredActivity
import org.thoughtcrime.securesms.util.DynamicNoActionBarTheme

/**
 * Blocking local gate shown when the app returns to the foreground and a local app PIN is enabled.
 * This is independent of Signal's account PIN and never contacts the server.
 */
class LocalAppPinActivity : PassphraseRequiredActivity() {
  private val dynamicTheme = DynamicNoActionBarTheme()
  private lateinit var pinInput: EditText
  private lateinit var status: TextView

  override fun onCreate(savedInstanceState: Bundle?, ready: Boolean) {
    super.onCreate(savedInstanceState, ready)
    if (!ready) return
    dynamicTheme.onCreate(this)
    window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)

    val density = resources.displayMetrics.density
    fun dp(value: Int) = (value * density).toInt()

    val content = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER_HORIZONTAL
      setPadding(dp(28), dp(28), dp(28), dp(28))
    }
    content.addView(TextView(this).apply {
      text = "App locked"
      textSize = 24f
      gravity = Gravity.CENTER
    })
    content.addView(TextView(this).apply {
      text = "Enter your local application PIN to continue. This PIN is stored and verified on this device only."
      textSize = 14f
      gravity = Gravity.CENTER
      setPadding(0, dp(12), 0, dp(24))
    })
    pinInput = EditText(this).apply {
      inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
      hint = "6–12 digit PIN"
      gravity = Gravity.CENTER
      textSize = 20f
      layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56))
    }
    content.addView(pinInput)
    status = TextView(this).apply {
      textSize = 13f
      gravity = Gravity.CENTER
      setPadding(0, dp(8), 0, dp(8))
    }
    content.addView(status)
    content.addView(Button(this).apply {
      text = "Unlock"
      isAllCaps = false
      setOnClickListener { unlock() }
      layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply {
        topMargin = dp(12)
      }
    })

    setContentView(ScrollView(this).apply {
      isFillViewport = true
      addView(content)
    })
    pinInput.requestFocus()
  }

  private fun unlock() {
    val pin = pinInput.text?.toString().orEmpty()
    if (LocalAppPinManager.verify(this, pin)) {
      finish()
      return
    }

    pinInput.text?.clear()
    val remaining = LocalAppPinManager.remainingLockoutMillis(this)
    status.text = if (remaining > 0L) {
      "Too many attempts. Try again in ${(remaining + 999L) / 1000L} seconds."
    } else {
      "Incorrect PIN. Try again."
    }
  }

  override fun onResume() {
    super.onResume()
    dynamicTheme.onResume(this)
  }

  @Deprecated("Use system back navigation; this lock cannot be dismissed without the PIN.")
  override fun onBackPressed() {
    moveTaskToBack(true)
  }
}
