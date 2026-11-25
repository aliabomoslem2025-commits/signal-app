package org.thoughtcrime.securesms.pin.lan;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Software LAN envelope v1. Uses standard PBKDF2-SHA256 and AES-256-GCM.
 * This protects the master key from plaintext storage, not from offline
 * guesses against a compromised server. It provides no hardware attestation.
 */
public final class LanRecoveryCrypto {
  public static final int ITERATIONS = 600_000;
  public static final String KDF = "PBKDF2-HMAC-SHA256";

  private LanRecoveryCrypto() {}

  public static byte[] derive(final String pin, final byte[] salt) throws GeneralSecurityException {
    if (pin == null || pin.isEmpty() || pin.length() > 1024 || salt.length != 16) {
      throw new IllegalArgumentException("Invalid LAN recovery PIN or salt");
    }
    final char[] normalized = Normalizer.normalize(pin, Normalizer.Form.NFKD).toCharArray();
    final PBEKeySpec specification = new PBEKeySpec(normalized, salt, ITERATIONS, 512);
    Arrays.fill(normalized, '\0');
    try {
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(specification).getEncoded();
    } finally {
      specification.clearPassword();
    }
  }

  public static byte[] verifier(final byte[] derived) {
    if (derived.length != 64) throw new IllegalArgumentException("Invalid derived key");
    return Arrays.copyOfRange(derived, 32, 64);
  }

  public static byte[] encrypt(final byte[] masterKey, final byte[] derived,
      final byte[] nonce, final String subject, final String revision) throws GeneralSecurityException {
    if (masterKey.length != 32) throw new IllegalArgumentException("Master key must have 32 bytes");
    return crypt(Cipher.ENCRYPT_MODE, masterKey, derived, nonce, subject, revision);
  }

  public static byte[] decrypt(final byte[] ciphertext, final byte[] derived,
      final byte[] nonce, final String subject, final String revision) throws GeneralSecurityException {
    if (ciphertext.length != 48) throw new IllegalArgumentException("Invalid encrypted master key length");
    final byte[] result = crypt(Cipher.DECRYPT_MODE, ciphertext, derived, nonce, subject, revision);
    if (result.length != 32) throw new GeneralSecurityException("Invalid decrypted master key length");
    return result;
  }

  private static byte[] crypt(final int mode, final byte[] input, final byte[] derived,
      final byte[] nonce, final String subject, final String revision) throws GeneralSecurityException {
    if (derived.length != 64 || nonce.length != 12 || subject == null || !subject.matches("[0-9a-f]{32}") ||
        revision == null || !revision.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
      throw new IllegalArgumentException("Invalid LAN recovery envelope parameters");
    }
    final byte[] key = Arrays.copyOf(derived, 32);
    try {
      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
      cipher.updateAAD(("signal-lan-recovery-v1\n" + subject + "\n" + revision).getBytes(StandardCharsets.UTF_8));
      return cipher.doFinal(input);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }
}
