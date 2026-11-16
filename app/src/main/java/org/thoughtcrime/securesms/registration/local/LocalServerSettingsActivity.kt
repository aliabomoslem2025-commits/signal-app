package org.thoughtcrime.securesms.registration.local

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONObject

/**
 * Public-only enrollment information; accessible before a user has an account.
 * QR encodes the entire enrollment JSON (Android ID + P-256 public key) so the
 * administrator can import a genuine device proof, not only a spoofable ID.
 * Never export the Keystore private key, app credentials or a server admin token.
 */
class LocalServerSettingsActivity : Activity() {

  private fun px(dp: Int): Int = (dp * resources.displayMetrics.density).toInt()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val padding = px(20)
    val content = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER_HORIZONTAL
      setPadding(padding, padding, padding, padding)
    }

    fun description(value: String, size: Float = 15f): TextView {
      return TextView(this).apply {
        text = value
        textSize = size
        setTextIsSelectable(true)
        setPadding(0, px(7), 0, px(7))
        content.addView(this, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
      }
    }

    description("ⓘ  اطلاعات دستگاه برای ثبت توسط مدیر", 23f)
    description("این اطلاعات شامل شناسه دستگاه و کلید عمومی است. کلید خصوصی هرگز از Android Keystore خارج نمی‌شود.")

    // The QR is generated offline, on this handset. No third-party QR server
    // receives the enrollment payload or any data about the user.
    val enrollment: JSONObject = try {
      LocalDeviceAuthClient(this).enrollmentInformation()
    } catch (e: Exception) {
      description("شناسه یا کلید ثبت دستگاه قابل دریافت نیست. لطفاً وضعیت امنیتی دستگاه را بررسی کنید.")
      setContentView(ScrollView(this).apply { addView(content) })
      return
    }
    val androidId = enrollment.getString("androidId")
    val payload = JSONObject()
      .put("formatVersion", 1)
      .put("androidId", androidId)
      .put("publicKeyPem", enrollment.getString("publicKeyPem"))
      .toString()

    try {
      val qr = qrBitmap(payload, 640)
      content.addView(ImageView(this).apply {
        setImageBitmap(qr)
        contentDescription = "QR کد ثبت دستگاه؛ شامل شناسه و کلید عمومی"
        adjustViewBounds = true
        scaleType = ImageView.ScaleType.FIT_CENTER
      }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, px(280)))
    } catch (e: Exception) {
      description("ساخت QR امکان‌پذیر نیست؛ اطلاعات متنی پایین را کپی یا اشتراک‌گذاری کنید.")
    }

    description("شناسه یکتای قابل مشاهده دستگاه (ANDROID_ID):", 16f)
    description(androidId, 20f).apply {
      gravity = Gravity.CENTER
      setTextIsSelectable(true)
    }
    content.addView(Button(this).apply {
      text = "کپی شناسه"
      setOnClickListener { copy("شناسه دستگاه", androidId) }
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

    content.addView(Button(this).apply {
      text = "کپی اطلاعات کامل ثبت دستگاه"
      setOnClickListener { copy("اطلاعات عمومی ثبت دستگاه", payload) }
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

    content.addView(Button(this).apply {
      text = "اشتراک‌گذاری برای مدیر"
      setOnClickListener {
        val send = Intent(Intent.ACTION_SEND).apply {
          type = "text/plain"
          putExtra(Intent.EXTRA_SUBJECT, "اطلاعات ثبت دستگاه Signal LAN")
          putExtra(Intent.EXTRA_TEXT, payload)
        }
        startActivity(Intent.createChooser(send, "اشتراک‌گذاری اطلاعات دستگاه"))
      }
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

    description("متن قابل واردکردن در داشبورد (کلید عمومی + شناسه):")
    description(payload, 12f)
    description("نکته: شناسه ANDROID_ID ممکن است پس از بازنشانی کارخانه‌ای تغییر کند. برای تأیید هویت، سرور امضای کلید خصوصی این دستگاه را نیز بررسی می‌کند.")

    setContentView(ScrollView(this).apply {
      fillViewport = true
      addView(content)
    })
  }

  private fun copy(label: String, text: String) {
    (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
      .setPrimaryClip(ClipData.newPlainText(label, text))
    Toast.makeText(this, "کپی شد", Toast.LENGTH_SHORT).show()
  }

  private fun qrBitmap(value: String, size: Int): Bitmap {
    val bits = QRCodeWriter().encode(
      value,
      BarcodeFormat.QR_CODE,
      size,
      size,
      mapOf(EncodeHintType.CHARACTER_SET to "UTF-8", EncodeHintType.MARGIN to 2)
    )
    return Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888).also { image ->
      val pixels = IntArray(size * size)
      for (y in 0 until size) {
        for (x in 0 until size) pixels[y * size + x] = if (bits.get(x, y)) Color.BLACK else Color.WHITE
      }
      image.setPixels(pixels, 0, size, 0, 0, size, size)
    }
  }
}
