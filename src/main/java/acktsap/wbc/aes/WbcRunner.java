/*
 * @copyright defined in LICENSE.txt
 */

package acktsap.wbc.aes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class WbcRunner {

  public static java.security.Key generateKey() {
    try {
      KeyGenerator generator = KeyGenerator.getInstance("AES");
      SecretKey key = generator.generateKey();
      return key;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static String decrypt(byte[] rawKey, String ciphertext) {
    try {
      byte[] rawCiphertext = java.util.Base64.getDecoder().decode(ciphertext);
      java.security.Key key = new SecretKeySpec(rawKey, "AES");
      Cipher c = Cipher.getInstance("AES");
      c.init(Cipher.DECRYPT_MODE, key);
      byte[] rawPlaintext = c.doFinal(rawCiphertext);

      String plaintext = new String(rawPlaintext);
      System.out.printf("Decrypted plaintext: %s%n", plaintext);
      return plaintext;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static void main(String[] args) {
    java.security.Key key = generateKey();

    PlainAes128 plainAes128 = new PlainAes128(key);
    // WbcAes128 wbcAes128 = new WbcAes128(key);

    // 1. run
    // 2. dump heap
    // 3. set rawKey from dump and ciphertext from stdout
    // 4. comment following block
    {
      String plaintext = "I'm plaintext";
      plainAes128.encrypt(plaintext);
      // wbcAes128.encrypt(plaintext);
      // wait for heap dump
      while (true);
    }

    // 5. uncomment following block
    // 6. run
    // {
    // // enter here raw key in a byte array [length=16]
    // byte[] rawKey = new byte[] {
    // };
    // String ciphertext = "PmP6JxIs8/9P2DFtllK9gg==";
    // decrypt(rawKey, ciphertext);
    // }
  }

}
