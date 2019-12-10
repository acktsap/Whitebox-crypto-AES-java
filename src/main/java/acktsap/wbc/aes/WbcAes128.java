/*
 * @copyright defined in LICENSE.txt
 */

package acktsap.wbc.aes;

import java.util.Base64;
import cz.muni.fi.xklinec.whiteboxAES.AES;
import cz.muni.fi.xklinec.whiteboxAES.State;
import cz.muni.fi.xklinec.whiteboxAES.generator.ExternalBijections;
import cz.muni.fi.xklinec.whiteboxAES.generator.Generator;

public class WbcAes128 {

  protected final java.security.Key key;

  public WbcAes128(java.security.Key key) {
    this.key = key;
    System.out.printf("[WbcAes128] - key: %s%n", new String(key.getEncoded()));
  }

  // TODO: not yet implemented
  public String encrypt(final String plaintext) {
    try {
      System.out.printf("[WbcAes128] < plaintext: %s%n", plaintext);

      Generator gEnc = new Generator();

      // External encoding is needed, at least some, generate identities
      ExternalBijections extc = new ExternalBijections();
      gEnc.generateExtEncoding(extc, Generator.WBAESGEN_EXTGEN_ID);

      // at first generate pure table AES implementation
      gEnc.setUseIO04x04Identity(true);
      gEnc.setUseIO08x08Identity(true);
      gEnc.setUseMB08x08Identity(true);
      gEnc.setUseMB32x32Identity(true);

      // Generate AES for encryption
      gEnc.generate(true, key.getEncoded(), 16, extc);
      AES AESenc = gEnc.getAESi();

      // Encrypt
      State state = new State(plaintext.getBytes(), true, false);
      state.transpose();
      AESenc.crypt(state);

      // Encode
      byte[] rawCiphertext = state.getState();
      String ciphertext = Base64.getEncoder().encodeToString(rawCiphertext);
      System.out.printf("[WbcAes128] > ciphertext: %s%n", ciphertext);

      return ciphertext;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
