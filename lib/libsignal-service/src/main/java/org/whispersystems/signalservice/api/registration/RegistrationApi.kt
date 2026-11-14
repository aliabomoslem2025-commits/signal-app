/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.signalservice.api.registration

import org.signal.network.NetworkResult
import org.whispersystems.signalservice.api.account.AccountAttributes
import org.whispersystems.signalservice.api.account.DeviceAttributes
import org.whispersystems.signalservice.api.account.PreKeyCollection
import org.whispersystems.signalservice.api.messages.multidevice.RegisterAsSecondaryDeviceResponse
import org.whispersystems.signalservice.api.provisioning.RestoreMethod
import org.whispersystems.signalservice.api.push.SignedPreKeyEntity
import org.whispersystems.signalservice.internal.push.BackupV2AuthCheckResponse
import org.whispersystems.signalservice.internal.push.BackupV3AuthCheckResponse
import org.whispersystems.signalservice.internal.push.NtfyTopicRegistration
import org.whispersystems.signalservice.internal.push.KyberPreKeyEntity
import org.whispersystems.signalservice.internal.push.PushServiceSocket
import org.whispersystems.signalservice.internal.push.RegisterAsSecondaryDeviceRequest
import org.whispersystems.signalservice.internal.push.RegistrationSessionMetadataResponse
import org.whispersystems.signalservice.internal.push.VerifyAccountResponse
import java.util.Locale

/**
 * Class to interact with various registration-related endpoints.
 */
class RegistrationApi(
  private val pushServiceSocket: PushServiceSocket
) {

  /**
   * Request that the service initialize a new registration session and associate this device's
   * ntfy topic with the session so the challenge can be delivered through the private LAN push service.
   *
   * `POST /v1/verification/session`
   */
  fun createRegistrationSession(ntfyTopic: String?, mcc: String?, mnc: String?): NetworkResult<RegistrationSessionMetadataResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.createVerificationSession(ntfyTopic, mcc, mnc)
    }
  }

  /**
   * Retrieve current status of a registration session.
   *
   * `GET /v1/verification/session/{session-id}`
   */
  fun getRegistrationSessionStatus(sessionId: String): NetworkResult<RegistrationSessionMetadataResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.getSessionStatus(sessionId)
    }
  }

  /**
   * Submit the ntfy-delivered registration challenge to the service.
   *
   * `PATCH /v1/verification/session/{session-id}`
   */
  fun submitPushChallengeToken(sessionId: String?, pushChallengeToken: String?): NetworkResult<RegistrationSessionMetadataResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.patchVerificationSession(sessionId, null, null, null, null, pushChallengeToken)
    }
  }

  /**
   * Request an SMS verification code. This legacy method remains for protocol compatibility;
   * LAN-only registration should use the local device authorization flow instead.
   */
  fun requestSmsVerificationCode(sessionId: String?, locale: Locale?, androidSmsRetrieverSupported: Boolean, transport: PushServiceSocket.VerificationCodeTransport): NetworkResult<RegistrationSessionMetadataResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.requestVerificationCode(sessionId, locale, androidSmsRetrieverSupported, transport)
    }
  }

  fun verifyAccount(sessionId: String, verificationCode: String): NetworkResult<RegistrationSessionMetadataResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.submitVerificationCode(sessionId, verificationCode)
    }
  }

  fun submitCaptchaToken(sessionId: String, captchaToken: String): NetworkResult<RegistrationSessionMetadataResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.patchVerificationSession(sessionId, null, null, null, captchaToken, null)
    }
  }

  fun registerAccount(sessionId: String?, recoveryPassword: String?, attributes: AccountAttributes?, aciPreKeys: PreKeyCollection?, pniPreKeys: PreKeyCollection?, ntfyTopic: String?, skipDeviceTransfer: Boolean): NetworkResult<VerifyAccountResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.submitRegistrationRequest(sessionId, recoveryPassword, attributes, aciPreKeys, pniPreKeys, ntfyTopic, skipDeviceTransfer)
    }
  }

  fun validateSvr2AuthCredential(e164: String, usernamePasswords: List<String>): NetworkResult<BackupV2AuthCheckResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.checkSvr2AuthCredentials(e164, usernamePasswords)
    }
  }

  fun validateSvr3AuthCredential(e164: String, usernamePasswords: List<String>): NetworkResult<BackupV3AuthCheckResponse> {
    return NetworkResult.fromFetch {
      pushServiceSocket.checkSvr3AuthCredentials(e164, usernamePasswords)
    }
  }

  fun setRestoreMethod(token: String, method: RestoreMethod): NetworkResult<Unit> {
    return NetworkResult.fromFetch {
      pushServiceSocket.setRestoreMethodChosen(token, RestoreMethodBody(method = method))
    }
  }

  fun registerAsSecondaryDevice(verificationCode: String, attributes: DeviceAttributes, aciPreKeys: PreKeyCollection, pniPreKeys: PreKeyCollection, ntfyTopic: String?): NetworkResult<RegisterAsSecondaryDeviceResponse> {
    val request = RegisterAsSecondaryDeviceRequest(
      verificationCode = verificationCode,
      accountAttributes = attributes,
      aciSignedPreKey = SignedPreKeyEntity(aciPreKeys.signedPreKey.id.toLong(), aciPreKeys.signedPreKey.keyPair.publicKey, aciPreKeys.signedPreKey.signature),
      pniSignedPreKey = SignedPreKeyEntity(pniPreKeys.signedPreKey.id.toLong(), pniPreKeys.signedPreKey.keyPair.publicKey, pniPreKeys.signedPreKey.signature),
      aciPqLastResortPreKey = KyberPreKeyEntity(aciPreKeys.lastResortKyberPreKey.id.toLong(), aciPreKeys.lastResortKyberPreKey.keyPair.publicKey, aciPreKeys.lastResortKyberPreKey.signature),
      pniPqLastResortPreKey = KyberPreKeyEntity(pniPreKeys.lastResortKyberPreKey.id.toLong(), pniPreKeys.lastResortKyberPreKey.keyPair.publicKey, pniPreKeys.lastResortKyberPreKey.signature),
      gcmToken = ntfyTopic?.let { NtfyTopicRegistration(it, true) }
    )

    return NetworkResult.fromFetch {
      pushServiceSocket.registerAsSecondaryDevice(request)
    }
  }
}
