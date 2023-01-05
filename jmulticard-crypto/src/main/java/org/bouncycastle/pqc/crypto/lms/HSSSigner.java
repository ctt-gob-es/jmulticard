package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class HSSSigner
    implements MessageSigner
{
    private HSSPrivateKeyParameters privKey;
    private HSSPublicKeyParameters pubKey;

    @Override
	public void init(final boolean forSigning, final CipherParameters param)
    {
         if (forSigning)
         {
             privKey = (HSSPrivateKeyParameters)param;
         }
         else
         {
             pubKey = (HSSPublicKeyParameters)param;
         }
    }

    @Override
	public byte[] generateSignature(final byte[] message)
    {
        try
        {
            return HSS.generateSignature(privKey, message).getEncoded();
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage());
        }
    }

    @Override
	public boolean verifySignature(final byte[] message, final byte[] signature)
    {
        try
        {
            return HSS.verifySignature(pubKey, HSSSignature.getInstance(signature, pubKey.getL()), message);
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("unable to decode signature: " + e.getMessage());
        }
    }
}
