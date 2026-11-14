package org.thoughtcrime.securesms.network.local;

import org.signal.network.config.TrustStore;
import org.thoughtcrime.securesms.push.SignalServiceTrustStore;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

/**
 * A private CA trust store for the configured LAN deployment. It trusts only certificates
 * explicitly supplied in server-config.json; it never installs a permissive trust manager.
 */
public final class LocalServerTrustStore implements TrustStore {
  private static final String PASSWORD = "signal-local-ca";
  private final byte[] keyStoreBytes;

  public LocalServerTrustStore(final Context context, final String caPem) throws Exception {
    if (caPem == null || caPem.isBlank()) {
      throw new IllegalArgumentException("A local CA certificate is required for LAN mode");
    }

    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(
        new ByteArrayInputStream(caPem.getBytes(StandardCharsets.US_ASCII)));
    if (certificates.isEmpty()) {
      throw new IllegalArgumentException("The configured local CA certificate is invalid");
    }

    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, PASSWORD.toCharArray());
    int index = 0;
    for (final Certificate certificate : certificates) {
      keyStore.setCertificateEntry("signal-lan-ca-" + index++, certificate);
    }

    try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      keyStore.store(output, PASSWORD.toCharArray());
      keyStoreBytes = output.toByteArray();
    }
  }

  @Override
  public InputStream getKeyStoreInputStream() {
    return new ByteArrayInputStream(keyStoreBytes);
  }

  @Override
  public String getKeyStorePassword() {
    return PASSWORD;
  }
}