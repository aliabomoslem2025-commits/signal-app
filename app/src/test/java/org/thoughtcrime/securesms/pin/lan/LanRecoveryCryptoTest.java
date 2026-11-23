package org.thoughtcrime.securesms.pin.lan;

import static org.junit.Assert.*;
import java.security.GeneralSecurityException;
import org.junit.Test;

public class LanRecoveryCryptoTest {
  private static final String SUBJECT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final String REVISION = "12345678-1234-4234-8234-1234567890ab";

  private static byte[] sequence(int count) {
    byte[] value = new byte[count];
    for (int i = 0; i < count; i++) value[i] = (byte) i;
    return value;
  }

  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    return result;
  }

  @Test public void matchesIndependentNodeCryptoVector() throws Exception {
    byte[] derived = LanRecoveryCrypto.derive("correct horse battery staple", sequence(16));
    assertArrayEquals(hex("ef177144eec9420cbc1093d2a8b344a92bc506d0d4ec9c028dd19f8324d8c1e60dfdc1b0fa4770d8351f72180401ea727d02dfd1d37e753361e8425f304d3293"), derived);
    byte[] encrypted = LanRecoveryCrypto.encrypt(sequence(32), derived, sequence(12), SUBJECT, REVISION);
    assertArrayEquals(hex("0ec78a8275b13a8be4208d48b0b086b2f588af38ca5f9123261f3d3e8b6bfb53522490eec39f8c5e092f877e72bbefc9"), encrypted);
    assertArrayEquals(sequence(32), LanRecoveryCrypto.decrypt(encrypted, derived, sequence(12), SUBJECT, REVISION));
  }

  @Test public void rejectsTamperedCiphertextAndDifferentSubject() throws Exception {
    byte[] derived = LanRecoveryCrypto.derive("recovery passphrase", sequence(16));
    byte[] encrypted = LanRecoveryCrypto.encrypt(sequence(32), derived, sequence(12), SUBJECT, REVISION);
    byte[] tampered = encrypted.clone();
    tampered[0] ^= 1;
    try {
      LanRecoveryCrypto.decrypt(tampered, derived, sequence(12), SUBJECT, REVISION);
      fail("Modified ciphertext accepted");
    } catch (GeneralSecurityException expected) {}
    try {
      LanRecoveryCrypto.decrypt(encrypted, derived, sequence(12), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", REVISION);
      fail("Different subject accepted");
    } catch (GeneralSecurityException expected) {}
    try {
      LanRecoveryCrypto.decrypt(encrypted, derived, sequence(12), SUBJECT, "22345678-1234-4234-8234-1234567890ab");
      fail("Different revision accepted");
    } catch (GeneralSecurityException expected) {}
  }

  @Test public void unicodeNormalizationIsStable() throws Exception {
    assertArrayEquals(LanRecoveryCrypto.derive("caf\u00e9 password", sequence(16)),
        LanRecoveryCrypto.derive("cafe\u0301 password", sequence(16)));
  }
}
