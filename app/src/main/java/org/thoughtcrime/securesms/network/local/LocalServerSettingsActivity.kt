package org.thoughtcrime.securesms.network.local

import android.content.ContentResolver
import android.net.Uri
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.thoughtcrime.securesms.registration.v2.localauth.LocalDeviceAuthClient

/**
 * On-device editor for the LAN-only endpoint file and exporter for public device enrollment material.
 */
class LocalServerSettingsActivity : AppCompatActivity() {
  private lateinit var configEditor: EditText
  private lateinit var pinEditor: EditText

  private val importConfig = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
    if (uri != null) readText(uri)?.let { configEditor.setText(it) }
  }

  private val exportConfig = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
    if (uri != null) {
      runCatching { LocalServerConfig.fromJson(configEditor.text.toString()).toJson() }
        .onSuccess { writeText(uri, it); toast("فایل تنظیمات صادر شد.") }
        .onFailure { toast(it.message ?: "فایل تنظیمات معتبر نیست.") }
    }
  }

  private val exportEnrollment = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
    if (uri != null) {
      runCatching { LocalDeviceAuthClient(this).exportEnrollmentJson() }
        .onSuccess { writeText(uri, it); toast("اطلاعات عمومی دستگاه صادر شد.") }
        .onFailure { toast(it.message ?: "صدور اطلاعات دستگاه انجام نشد.") }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(18), dp(18), dp(18), dp(24))
    }
    root.addView(TextView(this).apply {
      text = "تنظیمات شبکه محلی"
      textSize = 22f
    })
    root.addView(TextView(this).apply {
      text = "آدرس سرویس‌ها و گواهی CA را در فایل JSON مدیریت کنید. اعتبارسنجی TLS همیشه فعال است؛ از HTTP یا گواهی ناشناس استفاده نکنید."
      textSize = 14f
      setPadding(0, dp(8), 0, dp(12))
    })

    configEditor = EditText(this).apply {
      setText(runCatching { LocalServerConfigStore.load(this@LocalServerSettingsActivity).toJson() }
        .getOrElse { LocalServerConfig().toJson() })
      textSize = 11f
      typeface = android.graphics.Typeface.MONOSPACE
      minLines = 18
      gravity = android.view.Gravity.TOP or android.view.Gravity.START
      setHorizontallyScrolling(false)
      inputType = android.text.InputType.TYPE_CLASS_TEXT or
        android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
        android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }
    root.addView(configEditor, LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, dp(440)
    ))

    root.addView(button("واردکردن فایل تنظیمات") {
      importConfig.launch(arrayOf("application/json", "text/*"))
    })
    root.addView(button("ذخیره و اعمال تنظیمات") {
      runCatching {
        val config = LocalServerConfig.fromJson(configEditor.text.toString())
        LocalServerConfigStore.save(this, config)
      }.onSuccess {
        toast("تنظیمات ذخیره شد. برای بازسازی اتصالات شبکه، برنامه را کامل ببندید و دوباره باز کنید.")
      }.onFailure {
        toast(it.message ?: "تنظیمات معتبر نیست.")
      }
    })
    root.addView(button("خروجی گرفتن از فایل تنظیمات") {
      exportConfig.launch("server-config.json")
    })
    root.addView(button("خروجی اطلاعات عمومی دستگاه برای داشبورد") {
      exportEnrollment.launch("signal-device-enrollment.json")
    })
    root.addView(TextView(this).apply {
      text = "فایل اطلاعات دستگاه فقط شامل Android ID و کلید عمومی است. کلید خصوصی در Android Keystore باقی می‌ماند و هرگز صادر نمی‌شود. بعد از ذخیره تنظیمات، برنامه را مجدداً اجرا کنید."
      textSize = 12f
      setPadding(0, dp(12), 0, dp(18))
    })

    root.addView(TextView(this).apply {
      text = "قفل PIN محلی برنامه"
      textSize = 18f
      setPadding(0, dp(14), 0, dp(4))
    })
    root.addView(TextView(this).apply {
      text = if (LocalAppPinManager.isEnabled(this@LocalServerSettingsActivity)) {
        "PIN فعال است؛ هنگام بازگشت به برنامه درخواست می‌شود."
      } else {
        "PIN غیرفعال است."
      }
      textSize = 12f
    })
    pinEditor = EditText(this).apply {
      hint = "PIN شش تا دوازده رقمی"
      inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
      maxLines = 1
      filters = arrayOf(android.text.InputFilter.LengthFilter(12))
    }
    root.addView(pinEditor, LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    ))
    root.addView(button("فعال‌سازی یا تغییر PIN") {
      runCatching { LocalAppPinManager.setPin(this, pinEditor.text.toString()) }
        .onSuccess {
          pinEditor.text?.clear()
          toast("PIN فعال شد و هنگام بازگشت بعدی به برنامه درخواست می‌شود.")
        }
        .onFailure { toast(it.message ?: "PIN معتبر نیست.") }
    })
    root.addView(button("غیرفعال‌سازی PIN با PIN فعلی") {
      runCatching { LocalAppPinManager.disable(this, pinEditor.text.toString()) }
        .onSuccess {
          pinEditor.text?.clear()
          toast("قفل PIN غیرفعال شد.")
        }
        .onFailure { toast(it.message ?: "PIN فعلی صحیح نیست.") }
    })

    val scroll = ScrollView(this).apply { addView(root) }
    setContentView(scroll)
  }

  private fun button(label: String, action: () -> Unit): Button {
    return Button(this).apply {
      text = label
      setOnClickListener { action() }
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
      )
    }
  }

  private fun readText(uri: Uri): String? {
    return runCatching {
      contentResolver.openInputStream(uri)?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
        ?: throw IllegalStateException("خواندن فایل ممکن نشد.")
    }.onFailure { toast(it.message ?: "خطا در خواندن فایل.") }.getOrNull()
  }

  private fun writeText(uri: Uri, text: String) {
    try {
      contentResolver.openOutputStream(uri, ContentResolver.MODE_TRUNCATE)?.bufferedWriter(Charsets.UTF_8)?.use {
        it.write(text)
      } ?: throw IllegalStateException("نوشتن فایل ممکن نشد.")
    } catch (error: Exception) {
      toast(error.message ?: "خطا در ذخیره فایل.")
    }
  }

  private fun toast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show()
  }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}