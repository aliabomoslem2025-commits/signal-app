/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.registration.ntfy;

import androidx.annotation.NonNull;
import androidx.annotation.WorkerThread;

import org.signal.core.util.eventbus.EventBus;
import org.signal.core.util.logging.Log;

import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class PushChallengeRequest {

  private static final String TAG = Log.tag(PushChallengeRequest.class);

  private PushChallengeRequest() {}

  @WorkerThread
  public static Optional<String> getPushChallengeBlocking(@NonNull String ntfyTopic,
                                                          @NonNull String sessionId,
                                                          long timeoutMs) {
    if (ntfyTopic.isEmpty()) {
      Log.w(TAG, "Push challenge not requested because the ntfy topic is missing");
      return Optional.empty();
    }

    final long startTime = System.currentTimeMillis();
    final Request request = new Request(timeoutMs);
    final Optional<String> challenge = request.awaitChallenge();

    final long duration = System.currentTimeMillis() - startTime;
    if (challenge.isPresent()) {
      Log.i(TAG, String.format(Locale.US, "Received ntfy registration challenge in %d ms", duration));
    } else {
      Log.w(TAG, String.format(Locale.US, "Did not receive ntfy registration challenge in %d ms", duration));
    }
    return challenge;
  }

  public static void postChallengeResponse(@NonNull String challenge) {
    EventBus.getDefault().post(new PushChallengeEvent(challenge));
  }

  private static final class Request {
    private final CountDownLatch latch = new CountDownLatch(1);
    private final AtomicReference<String> challenge = new AtomicReference<>();
    private final long timeoutMs;

    private Request(long timeoutMs) {
      this.timeoutMs = timeoutMs;
    }

    private Optional<String> awaitChallenge() {
      final EventBus.Subscription subscription = EventBus.getDefault().subscribe(
          PushChallengeEvent.class, this::onChallengeEvent);
      try {
        latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        return Optional.ofNullable(challenge.get());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        Log.w(TAG, "Interrupted while waiting for ntfy registration challenge", e);
        return Optional.empty();
      } finally {
        subscription.unsubscribe();
      }
    }

    private void onChallengeEvent(@NonNull PushChallengeEvent event) {
      challenge.compareAndSet(null, event.challenge);
      latch.countDown();
    }
  }

  public static final class PushChallengeEvent {
    private final String challenge;

    PushChallengeEvent(@NonNull String challenge) {
      this.challenge = challenge;
    }

    public String getChallenge() {
      return challenge;
    }
  }
}
