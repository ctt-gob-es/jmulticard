package org.bouncycastle.pqc.crypto;


import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Base interface for a PQC encryption algorithm.
 */
public interface MessageEncryptor
{

    /**
     *
     * @param forEncrypting true if we are encrypting a signature, false
     * otherwise.
     * @param param key parameters for encryption or decryption.
     */
    void init(boolean forEncrypting, CipherParameters param);

    /**
     *
     * @param message the message to be signed.
     * @return Encrypted message.
     */
    byte[] messageEncrypt(byte[] message);

    /**
     *
     * @param cipher the cipher text of the message
     * @return Decrypted message.
     * @throws InvalidCipherTextException if the text can't be dechipered.
     */
    byte[] messageDecrypt(byte[] cipher)
        throws InvalidCipherTextException;
}
