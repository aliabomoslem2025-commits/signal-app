package org.thoughtcrime.securesms.push;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;
import org.signal.network.config.TrustStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

/**
 * Runtime trust store for the private LAN Signal deployment.
 *
 * A private CA must be explicitly imported in server-config.json. The system trust manager continues to validate
 * the server certificate chain; this class does not install a permissive trust manager or accept all certificates.
 */
public final class LocalServerTrustStore implements TrustStore {
  private static final String PREFS = "local_server_configuration";
  private static final String KEY_CONFIG = "config_json";
  private static final String PASSWORD = "signal-local-ca";
  private final Context context;

  public LocalServerTrustStore(final Context context) {
    this.context = context.getApplicationContext();
  }

  @Override
  public InputStream getKeyStoreInputStream() {
    try {
      final SharedPreferences preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
      final String configJson = preferences.getString(KEY_CONFIG, null);
      final String pem;
      if (configJson == null) {
        try (InputStream input = context.getAssets().open("server-config.json")) {
          final ByteArrayOutputStream assetBytes = new ByteArrayOutputStream();
          final byte[] buffer = new byte[4096];
          int count;
          while ((count = input.read(buffer)) != -1) {
            assetBytes.write(buffer, 0, count);
          }
          pem = new JSONObject(new String(assetBytes.toByteArray(), StandardCharsets.UTF_8)).optString("trustedCaPem");
        }
      } else {
        pem = new JSONObject(configJson).optString("trustedCaPem");
      }

      if (pem == null || !pem.contains("-----BEGIN CERTIFICATE-----")) {
        throw new IllegalStateException("Import your private LAN CA certificate in Settings > Local Server before connecting.");
      }

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      final Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(
          new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
      if (certificates.isEmpty()) {
        throw new IllegalStateException("The configured private CA PEM contains no certificates.");
      }

      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
      int index = 0;
      for (final Certificate certificate : certificates) {
        keyStore.setCertificateEntry("local-lan-ca-" + index++, certificate);
      }

      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      keyStore.store(output, PASSWORD.toCharArray());
      return new ByteArrayInputStream(output.toByteArray());
    } catch (final IllegalStateException e) {
      throw e;
    } catch (final Exception e) {
      throw new IllegalStateException("Could not load the private LAN CA certificate.", e);
    }
  }

  @Override
  public String getKeyStorePassword() {
    return PASSWORD;
  }
}
