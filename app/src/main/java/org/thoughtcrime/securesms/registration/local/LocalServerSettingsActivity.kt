package org.thoughtcrime.securesms.registration.local

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import org.json.JSONObject
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.signal.core.ui.compose.theme.SignalTheme
import org.thoughtcrime.securesms.dependencies.AppDependencies

/**
 * Editable runtime LAN endpoints, CA trust anchor and device enrollment export.
 *
 * Imported JSON is validated before it is committed to app-private SharedPreferences. Private keys are never exported.
 */
class LocalServerSettingsActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContent {
      SignalTheme {
        LocalServerSettingsScreen(
          initialConfig = LocalServerConfig.load(this),
          onBack = { finish() }
        )
      }
    }
  }
}

@Composable
private fun LocalServerSettingsScreen(
  initialConfig: LocalServerConfig,
  onBack: () -> Unit
) {
  val context = LocalContext.current
  var json by rememberSaveable { mutableStateOf(initialConfig.exportJson()) }
  var error by rememberSaveable { mutableStateOf<String?>(null) }
  var currentPin by rememberSaveable { mutableStateOf("") }
  var pin by rememberSaveable { mutableStateOf("") }
  var confirmPin by rememberSaveable { mutableStateOf("") }
  var pinEnabled by remember { mutableStateOf(LocalPinLockManager.isEnabled(context)) }

  Scaffold(
    topBar = {
      Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween
      ) {
        TextButton(onClick = onBack) { Text("Back") }
        Text("Local server", style = MaterialTheme.typography.titleLarge)
        TextButton(onClick = {
          copyToClipboard(context, "server-config.json", initialConfig.exportJson())
          Toast.makeText(context, "Configuration copied", Toast.LENGTH_SHORT).show()
        }) { Text("Export") }
      }
    }
  ) { padding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(padding)
        .verticalScroll(rememberScrollState())
        .padding(16.dp),
      verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
      Text(
        "Paste or edit server-config.json. Use HTTPS for every LAN service and include your private CA certificate in trustedCaPem. Certificate validation cannot be disabled.",
        style = MaterialTheme.typography.bodyMedium
      )

      OutlinedTextField(
        value = json,
        onValueChange = {
          json = it
          error = null
        },
        modifier = Modifier.fillMaxWidth().heightIn(min = 360.dp),
        minLines = 18,
        label = { Text("server-config.json") },
        supportingText = { Text("The file is stored in app-private storage. Do not put passwords or bearer tokens in this file.") }
      )

      error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

      Button(
        onClick = {
          try {
            initialConfig.importJson(json)
            AppDependencies.resetNetwork()
            AppDependencies.startNetwork()
            json = initialConfig.exportJson()
            error = null
            Toast.makeText(context, "Server configuration saved. Network settings will be reloaded.", Toast.LENGTH_LONG).show()
          } catch (e: Exception) {
            error = e.message ?: "Invalid configuration"
          }
        },
        modifier = Modifier.fillMaxWidth()
      ) {
        Text("Validate and save configuration")
      }

      Text("Local application PIN", style = MaterialTheme.typography.titleMedium)
      Text(
        if (pinEnabled) "A separate local PIN is enabled. The app will request it when returning from the background."
        else "Optional. Set a 6–12 digit PIN to lock this app when it returns from the background.",
        style = MaterialTheme.typography.bodyMedium
      )
      if (pinEnabled) {
        OutlinedTextField(
          value = currentPin,
          onValueChange = { value -> if (value.length <= 12 && value.all(Char::isDigit)) currentPin = value },
          modifier = Modifier.fillMaxWidth(),
          label = { Text("Current local PIN") },
          singleLine = true,
          keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword),
          visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation()
        )
      }
      OutlinedTextField(
        value = pin,
        onValueChange = { value -> if (value.length <= 12 && value.all(Char::isDigit)) pin = value },
        modifier = Modifier.fillMaxWidth(),
        label = { Text(if (pinEnabled) "New local PIN" else "New local PIN") },
        singleLine = true,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword),
        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation()
      )
      OutlinedTextField(
        value = confirmPin,
        onValueChange = { value -> if (value.length <= 12 && value.all(Char::isDigit)) confirmPin = value },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("Confirm local PIN") },
        singleLine = true,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword),
        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation()
      )
      Button(
        onClick = {
          try {
            require(pin == confirmPin) { "PIN confirmation does not match" }
            val changingExistingPin = pinEnabled
            if (changingExistingPin) {
              require(currentPin.length in 6..12) { "Enter the current PIN first" }
              require(LocalPinLockManager.changePin(context, currentPin, pin)) { "Current PIN is incorrect or temporarily locked" }
            } else {
              LocalPinLockManager.setPin(context, pin)
            }
            currentPin = ""
            pin = ""
            confirmPin = ""
            pinEnabled = true
            error = null
            Toast.makeText(context, if (changingExistingPin) "Local app PIN changed" else "Local app PIN enabled", Toast.LENGTH_LONG).show()
          } catch (e: Exception) {
            error = e.message ?: "Could not save local PIN"
          }
        },
        enabled = pin.length in 6..12 && confirmPin.length in 6..12 && (!pinEnabled || currentPin.length in 6..12),
        modifier = Modifier.fillMaxWidth()
      ) {
        Text(if (pinEnabled) "Change local PIN" else "Enable local PIN")
      }
      if (pinEnabled) {
        TextButton(onClick = {
          if (currentPin.length !in 6..12 || !LocalPinLockManager.removePin(context, currentPin)) {
            error = "Current PIN is incorrect or temporarily locked"
          } else {
            pinEnabled = false
            currentPin = ""
            pin = ""
            confirmPin = ""
            error = null
            Toast.makeText(context, "Local app PIN removed", Toast.LENGTH_LONG).show()
          }
        }) {
          Text("Disable local PIN")
        }
      }

      Text("Device enrollment", style = MaterialTheme.typography.titleMedium)
      Text(
        "Copy the Android ID and public key below, then enroll them for the selected phone number in the LAN administration dashboard. The private key remains inside Android Keystore.",
        style = MaterialTheme.typography.bodyMedium
      )
      Button(
        onClick = {
          try {
            val keyStore = LocalDeviceAuthKeyStore(context)
            val bundle = JSONObject()
              .put("formatVersion", 1)
              .put("androidId", keyStore.androidId())
              .put("publicKeyPem", keyStore.publicKeyPem())
              .toString(2)
            copyToClipboard(context, "Signal LAN device enrollment JSON", bundle)
            Toast.makeText(context, "Device enrollment JSON copied", Toast.LENGTH_LONG).show()
          } catch (e: Exception) {
            error = e.message ?: "Could not export device public key"
          }
        },
        modifier = Modifier.fillMaxWidth()
      ) {
        Text("Copy device enrollment information")
      }

      Text(
        "Important: Android ID is only a lookup value. Server authentication also requires the device's ECDSA key proof. Reinstalling the app or resetting the device may require re-enrollment.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
      )
    }
  }
}

private fun copyToClipboard(context: Context, label: String, value: String) {
  val clipboard = context.getSystemService(ClipboardManager::class.java)
  clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
}
