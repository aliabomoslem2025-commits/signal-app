package org.thoughtcrime.securesms.network.local

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Blocking local app-unlock screen. It never sends the PIN to the Signal server.
 */
class LocalAppPinActivity : AppCompatActivity() {
  private lateinit var pinInput: EditText
  private lateinit var statusText: TextView
  private lateinit var unlockButton: Button
  private val handler = Handler(Looper.getMainLooper())

  private val refreshLockout = object : Runnable {
    override fun run() {
      val remaining = LocalAppPinManager.remainingLockMillis(this@LocalAppPinActivity)
      unlockButton.isEnabled = remaining == 0L
      if (remaining > 0) {
        statusText.text = "به دلیل تلاش‌های ناموفق، ورود تا ${(remaining + 999) / 1000} ثانیه دیگر قفل است."
        handler.postDelayed(this, 1_000L)
      } else if (!unlockButton.isEnabled) {
        statusText.text = "PIN را وارد کنید."
        unlockButton.isEnabled = true
      }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE
    )
    window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)

    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER
      setPadding(dp(28), dp(28), dp(28), dp(28))
    }
    root.addView(TextView(this).apply {
      text = "قفل برنامه"
      textSize = 24f
      gravity = Gravity.CENTER
    })
    root.addView(TextView(this).apply {
      text = "برای دسترسی به پیام‌ها PIN محلی خود را وارد کنید."
      textSize = 14f
      gravity = Gravity.CENTER
      setPadding(0, dp(10), 0, dp(20))
    })
    pinInput = EditText(this).apply {
      hint = "PIN"
      gravity = Gravity.CENTER
      inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
      maxLines = 1
      filters = arrayOf(android.text.InputFilter.LengthFilter(12))
    }
    root.addView(pinInput, LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    ))
    statusText = TextView(this).apply {
      gravity = Gravity.CENTER
      textSize = 12f
      setPadding(0, dp(12), 0, dp(12))
    }
    root.addView(statusText)
    unlockButton = Button(this).apply {
      text = "باز کردن قفل"
      setOnClickListener { tryUnlock() }
    }
    root.addView(unlockButton, LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    ))
    setContentView(root)
    pinInput.requestFocus()
    refreshLockout.run()
  }

  private fun tryUnlock() {
    val pin = pinInput.text?.toString().orEmpty()
    if (LocalAppPinManager.verify(this, pin)) {
      finish()
    } else {
      pinInput.text?.clear()
      val remaining = LocalAppPinManager.remainingLockMillis(this)
      statusText.text = if (remaining > 0) {
        "PIN اشتباه است. قفل موقت فعال شد."
      } else {
        "PIN صحیح نیست."
      }
      refreshLockout.run()
    }
  }

  @Deprecated("PIN gate cannot be dismissed with the back button")
  override fun onBackPressed() {
    // Deliberately keep the application behind the lock screen.
  }

  override fun onDestroy() {
    handler.removeCallbacksAndMessages(null)
    super.onDestroy()
  }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}