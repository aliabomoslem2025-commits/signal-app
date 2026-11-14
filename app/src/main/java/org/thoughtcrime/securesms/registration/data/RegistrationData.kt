package org.thoughtcrime.securesms.registration.data

import org.signal.libsignal.zkgroup.profiles.ProfileKey

data class RegistrationData(
  val code: String,
  val e164: String,
  val password: String,
  val registrationId: Int,
  val profileKey: ProfileKey,
  val pniRegistrationId: Int,
  val recoveryPassword: String?
) {
}
