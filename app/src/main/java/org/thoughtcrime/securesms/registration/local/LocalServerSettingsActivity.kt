package org.thoughtcrime.securesms.registration.local

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
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
            json = initialConfig.exportJson()
            error = null
            Toast.makeText(context, "Server configuration saved", Toast.LENGTH_LONG).show()
          } catch (e: Exception) {
            error = e.message ?: "Invalid configuration"
          }
        },
        modifier = Modifier.fillMaxWidth()
      ) {
        Text("Validate and save configuration")
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
            val bundle = buildString {
              append("Android ID: ")
              append(keyStore.androidId())
              append("\n\n")
              append(keyStore.publicKeyPem())
            }
            copyToClipboard(context, "Signal LAN device enrollment", bundle)
            Toast.makeText(context, "Android ID and public key copied", Toast.LENGTH_LONG).show()
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
