/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.registration.ntfy;

import androidx.annotation.NonNull;
import androidx.annotation.WorkerThread;

import org.signal.core.util.eventbus.EventBus;
import org.signal.core.util.logging.Log;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;

import java.io.IOException;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Performs Signal's existing registration push challenge over the ntfy transport. */
public final class PushChallengeRequest {

  private static final String TAG = Log.tag(PushChallengeRequest.class);

  private PushChallengeRequest() {}

  @WorkerThread
  public static Optional<String> getPushChallengeBlocking(@NonNull SignalServiceAccountManager accountManager,
                                                          @NonNull String sessionId,
                                                          @NonNull String ntfyTopic,
                                                          long timeoutMs) {
    if (ntfyTopic.isEmpty()) {
      Log.w(TAG, "Push challenge not requested because the ntfy topic is missing");
      return Optional.empty();
    }

    final long startTime = System.currentTimeMillis();
    final Request request = new Request(accountManager, ntfyTopic, sessionId, timeoutMs);
    final Optional<String> challenge = request.requestAndReceiveChallengeBlocking();

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
    private final SignalServiceAccountManager accountManager;
    private final String ntfyTopic;
    private final String sessionId;
    private final long timeoutMs;

    private Request(@NonNull SignalServiceAccountManager accountManager,
                    @NonNull String ntfyTopic,
                    @NonNull String sessionId,
                    long timeoutMs) {
      this.accountManager = accountManager;
      this.ntfyTopic = ntfyTopic;
      this.sessionId = sessionId;
      this.timeoutMs = timeoutMs;
    }

    @WorkerThread
    private Optional<String> requestAndReceiveChallengeBlocking() {
      final EventBus.Subscription subscription = EventBus.getDefault().subscribe(
          PushChallengeEvent.class, this::onChallengeEvent);
      try {
        accountManager.requestRegistrationPushChallenge(sessionId, ntfyTopic);
        latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        return Optional.ofNullable(challenge.get());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        Log.w(TAG, "Interrupted while waiting for ntfy registration challenge", e);
        return Optional.empty();
      } catch (IOException e) {
        Log.w(TAG, "Unable to request ntfy registration challenge", e);
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
