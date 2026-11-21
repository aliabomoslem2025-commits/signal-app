package org.thoughtcrime.securesms.jobs;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.signal.core.util.logging.Log;
import org.thoughtcrime.securesms.push.NtfyPushService;
import org.thoughtcrime.securesms.keyvalue.SignalStore;
import org.thoughtcrime.securesms.jobmanager.Job;

/**
 * One-time migration for persisted jobs from LAN builds that still used the
 * FCM job key. It clears the legacy token state and starts the embedded ntfy
 * subscriber for registered accounts.
 */
public final class NtfyPushSetupJob extends BaseJob {
  public static final String KEY = "NtfyPushSetupJob";
  private static final String TAG = Log.tag(NtfyPushSetupJob.class);

  public NtfyPushSetupJob() {
    this(new Job.Parameters.Builder()
        .setQueue("NtfyPushSetupJob")
        .setMaxAttempts(3)
        .setMaxInstancesForFactory(1)
        .build());
  }

  private NtfyPushSetupJob(@NonNull Job.Parameters parameters) {
    super(parameters);
  }

  @Override
  public @Nullable byte[] serialize() {
    return null;
  }

  @Override
  public @NonNull String getFactoryKey() {
    return KEY;
  }

  @Override
  public void onRun() {
    // These fields are retained only so older account records can be migrated.
    SignalStore.account().setFcmEnabled(false);
    SignalStore.account().setFcmToken(null);
    if (SignalStore.account().isRegistered()) {
      NtfyPushService.start(context);
    }
  }

  @Override
  protected boolean onShouldRetry(@NonNull Exception e) {
    return true;
  }

  @Override
  public void onFailure() {
    Log.w(TAG, "Legacy push migration job failed; the application startup path will retry ntfy setup.");
  }

  public static final class Factory implements Job.Factory<NtfyPushSetupJob> {
    @Override
    public @NonNull NtfyPushSetupJob create(@NonNull Parameters parameters, @Nullable byte[] serializedData) {
      return new NtfyPushSetupJob(parameters);
    }
  }
}
