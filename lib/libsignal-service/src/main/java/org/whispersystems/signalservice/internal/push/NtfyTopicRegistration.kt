/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.signalservice.internal.push

import com.fasterxml.jackson.annotation.JsonProperty

/**
 * Android ntfy routing topic transported through Signal's legacy gcmRegistrationId JSON slot.
 * Keeping the wire key stable avoids breaking the DeviceActivationRequest schema while the
 * server stores the opaque topic instead of an FCM registration token.
 */
data class NtfyTopicRegistration(
  @JsonProperty val gcmRegistrationId: String,
  @JsonProperty val webSocketChannel: Boolean
)
