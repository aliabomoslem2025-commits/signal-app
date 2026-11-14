package org.thoughtcrime.securesms.push;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;
import org.signal.network.config.TrustStore;
import org.thoughtcrime.securesms.R;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

/**
 * Trust store for the locally configured Signal deployment.
 *
 * The packaged Signal trust store is retained and administrator-supplied private LAN CA roots are
 * added to it. Certificate validation is never disabled and no trust-all manager is installed.
 */
public final class LocalServerTrustStore implements TrustStore {
  private static final String PREFS_NAME = "local_server_config";
  private static final String CONFIG_KEY = "config_json";
  private static final String PASSWORD = "whisper";

  private final Context context;

  public LocalServerTrustStore(final Context context) {
    this.context = context.getApplicationContext();
  }

  @Override
  public InputStream getKeyStoreInputStream() {
    try {
      final String jsonText = loadConfigJson();
      final String pem = new JSONObject(jsonText).optString("trustedCaPem", "").trim();

      if (pem.isEmpty()) {
        // Preserve existing Signal trust roots until an administrator imports the private LAN CA.
        return context.getResources().openRawResource(R.raw.whisper);
      }

      final KeyStore keyStore = KeyStore.getInstance("BKS");
      try (InputStream packagedTrustStore = context.getResources().openRawResource(R.raw.whisper)) {
        keyStore.load(packagedTrustStore, PASSWORD.toCharArray());
      }

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(
          new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
      if (certificates.isEmpty()) {
        throw new IllegalArgumentException("trustedCaPem contains no X.509 certificates");
      }

      int index = 0;
      for (final Certificate certificate : certificates) {
        keyStore.setCertificateEntry("local-lan-ca-" + index++, certificate);
      }

      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      keyStore.store(output, PASSWORD.toCharArray());
      return new ByteArrayInputStream(output.toByteArray());
    } catch (final Exception e) {
      throw new IllegalStateException("Could not load the configured LAN CA certificate.", e);
    }
  }

  @Override
  public String getKeyStorePassword() {
    return PASSWORD;
  }

  private String loadConfigJson() throws Exception {
    final SharedPreferences preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    final String saved = preferences.getString(CONFIG_KEY, null);
    if (saved != null) {
      return saved;
    }

    try (InputStream input = context.getAssets().open("server-config.json");
         ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      final byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) != -1) {
        output.write(buffer, 0, count);
      }
      return output.toString(StandardCharsets.UTF_8.name());
    }
  }
}
