package org.thoughtcrime.securesms.push;

import android.content.Context;
import org.signal.network.config.TrustStore;
import org.thoughtcrime.securesms.registration.local.LocalServerConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

/** Trusts ONLY the administrator's bundled LAN CA, never an all-trusting TrustManager. */
public final class LocalServerTrustStore implements TrustStore {
  private final Context context;

  public LocalServerTrustStore(Context context) {
    this.context = context.getApplicationContext();
  }

  @Override
  public InputStream getKeyStoreInputStream() {
    try {
      final String pem = LocalServerConfig.Companion.load(context).getTrustedCaPem();
      if (!pem.contains("-----BEGIN CERTIFICATE-----")) {
        throw new IllegalStateException("Set the actual LAN CA PEM in server-config.json before deployment");
      }
      final CertificateFactory factory = CertificateFactory.getInstance("X.509");
      final Collection<? extends java.security.cert.Certificate> certificates =
          factory.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
      if (certificates.isEmpty()) {
        throw new IllegalStateException("LAN CA PEM contains no certificates");
      }
      final KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(null, getKeyStorePassword().toCharArray());
      int index = 0;
      for (java.security.cert.Certificate certificate : certificates) {
        if (!(certificate instanceof X509Certificate)) {
          throw new IllegalStateException("LAN trust root must be X.509");
        }
        ks.setCertificateEntry("lan-ca-" + index++, certificate);
      }
      final ByteArrayOutputStream data = new ByteArrayOutputStream();
      ks.store(data, getKeyStorePassword().toCharArray());
      return new ByteArrayInputStream(data.toByteArray());
    } catch (Exception error) {
      throw new IllegalStateException("Could not load LAN certificate trust store", error);
    }
  }

  @Override
  public String getKeyStorePassword() {
    return "lan-bundled-ca";
  }
}
