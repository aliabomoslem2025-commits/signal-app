/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.thoughtcrime.securesms.registration.ntfy;

import androidx.annotation.NonNull;

import org.signal.core.util.eventbus.EventBus;

/**
 * Delivers Signal registration challenge tokens received over the private ntfy transport to
 * the active registration flow. ntfy carries only the short-lived challenge, never message data.
 */
public final class PushChallengeRequest {
  private PushChallengeRequest() {}

  public static void postChallengeResponse(@NonNull final String challenge) {
    if (challenge.isBlank()) {
      throw new IllegalArgumentException("Registration challenge must not be blank");
    }
    EventBus.getDefault().post(new PushChallengeEvent(challenge));
  }

  public static final class PushChallengeEvent {
    private final String challenge;

    public PushChallengeEvent(@NonNull final String challenge) {
      this.challenge = challenge;
    }

    @NonNull
    public String getChallenge() {
      return challenge;
    }
  }
}
