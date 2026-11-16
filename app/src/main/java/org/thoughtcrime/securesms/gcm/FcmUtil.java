package org.thoughtcrime.securesms.gcm;

import android.content.Context;
import android.text.TextUtils;

import androidx.annotation.WorkerThread;


import org.signal.core.util.logging.Log;

import java.util.Optional;

public final class FcmUtil {

  private static final String TAG = Log.tag(FcmUtil.class);

  /**
   * Retrieves the current FCM token. If one isn't available, it'll be generated.
   */
  @WorkerThread
  public static Optional<String> getToken(Context context) {
    // The self-hosted LAN build has no Firebase token or dependency on Google
    // Play Services. The server provisions a private ntfy topic instead.
    return Optional.empty();
  }
}
