package org.bouncycastle.crypto;

public interface EncapsulatedSecretExtractor
{
    /**
     * Generate an exchange pair based on the recipient public key.
     *
     * @param encapsulation the encapsulated secret.
     * @return Secret.
     */
    byte[] extractSecret(byte[] encapsulation);
}
