/*
 * @copyright defined in LICENSE.txt
 */

package acktsap.wbc.aes;

import java.security.Key;
import javax.crypto.Cipher;

public class PlainAes128 {

  protected final java.security.Key key;

  public PlainAes128(Key key) {
    this.key = key;
    System.out.printf("[PlainAes128] - key: %s%n", new String(key.getEncoded()));
  }

  public String encrypt(String plaintext) {
    try {
      System.out.printf("[PlainAes128] < plaintext: %s%n", plaintext);

      // Encrypt
      Cipher c = Cipher.getInstance("AES");
      c.init(Cipher.ENCRYPT_MODE, key);
      byte[] rawCiphertext = c.doFinal(plaintext.getBytes());

      // Encode
      String ciphertext = java.util.Base64.getEncoder().encodeToString(rawCiphertext);
      System.out.printf("[PlainAes128] > ciphertext: %s%n", ciphertext);

      return ciphertext;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
