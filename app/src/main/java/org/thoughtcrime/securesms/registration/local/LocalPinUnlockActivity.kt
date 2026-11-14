package org.thoughtcrime.securesms.registration.local

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.signal.core.ui.compose.theme.SignalTheme

class LocalPinUnlockActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContent {
      SignalTheme {
        LocalPinUnlockScreen(
          onUnlocked = { finish() },
          onPinDisabled = { finish() }
        )
      }
    }
  }
}

@Composable
private fun LocalPinUnlockScreen(
  onUnlocked: () -> Unit,
  onPinDisabled: () -> Unit
) {
  val context = LocalContext.current
  var pin by rememberSaveable { mutableStateOf("") }
  var error by rememberSaveable { mutableStateOf<String?>(null) }
  var lockoutRemaining by remember { mutableLongStateOf(LocalPinLockManager.lockoutRemainingMs(context)) }

  BackHandler(enabled = true) { }

  LaunchedEffect(Unit) {
    if (!LocalPinLockManager.isEnabled(context)) {
      onPinDisabled()
      return@LaunchedEffect
    }
    while (true) {
      lockoutRemaining = LocalPinLockManager.lockoutRemainingMs()
      delay(500)
    }
  }

  Scaffold { padding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(padding)
        .padding(28.dp),
      verticalArrangement = Arrangement.Center
    ) {
      Text("App is locked", style = MaterialTheme.typography.headlineMedium)
      Text(
        "Enter your local application PIN to continue. This PIN is stored only on this device and is not sent to the server.",
        modifier = Modifier.padding(top = 12.dp, bottom = 24.dp),
        style = MaterialTheme.typography.bodyMedium
      )
      OutlinedTextField(
        value = pin,
        onValueChange = { value ->
          if (value.length <= 12 && value.all(Char::isDigit)) pin = value
          error = null
        },
        modifier = Modifier.fillMaxWidth(),
        label = { Text("6–12 digit PIN") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        visualTransformation = PasswordVisualTransformation()
      )
      error?.let {
        Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 10.dp))
      }
      if (lockoutRemaining > 0) {
        Text(
          "Too many attempts. Try again in ${(lockoutRemaining + 999) / 1000} seconds.",
          color = MaterialTheme.colorScheme.error,
          modifier = Modifier.padding(top = 10.dp)
        )
      }
      Button(
        onClick = {
          if (LocalPinLockManager.verifyPin(context, pin)) {
            pin = ""
            onUnlocked()
          } else {
            error = if (LocalPinLockManager.lockoutRemainingMs() > 0) {
              "PIN attempts are temporarily locked."
            } else {
              "Incorrect PIN."
            }
            pin = ""
            lockoutRemaining = LocalPinLockManager.lockoutRemainingMs()
          }
        },
        enabled = pin.length in 6..12 && lockoutRemaining == 0L,
        modifier = Modifier.fillMaxWidth().padding(top = 20.dp)
      ) {
        Text("Unlock")
      }
    }
  }
}
