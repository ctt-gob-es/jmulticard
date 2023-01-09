package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class LMSSigner
    implements MessageSigner
{
    private LMSPrivateKeyParameters privKey;
    private LMSPublicKeyParameters pubKey;

    @Override
	public void init(final boolean forSigning, final CipherParameters param)
    {
         if (forSigning)
         {
             privKey = (LMSPrivateKeyParameters)param;
         }
         else
         {
             pubKey = (LMSPublicKeyParameters)param;
         }
    }

    @Override
	public byte[] generateSignature(final byte[] message)
    {
        try
        {
            return LMS.generateSign(privKey, message).getEncoded();
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
            return LMS.verifySignature(pubKey, LMSSignature.getInstance(signature), message);
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("unable to decode signature: " + e.getMessage());
        }
    }
}
