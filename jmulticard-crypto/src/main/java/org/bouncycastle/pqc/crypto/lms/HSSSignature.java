package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

public class HSSSignature
    implements Encodable
{
    private final int lMinus1;
    private final LMSSignedPubKey[] signedPubKey;
    private final LMSSignature signature;

    public HSSSignature(final int lMinus1, final LMSSignedPubKey[] signedPubKey, final LMSSignature signature)
    {
        this.lMinus1 = lMinus1;
        this.signedPubKey = signedPubKey;
        this.signature = signature;
    }


    /**
     * @param src byte[], InputStream or HSSSignature
     * @param L   The HSS depth, available from public key.
     * @return An HSSSignature instance.
     * @throws IOException If IO error occurs.
     */
    public static HSSSignature getInstance(final Object src, final int L)
        throws IOException
    {
        if (src instanceof HSSSignature)
        {
            return (HSSSignature)src;
        }
        else if (src instanceof DataInputStream)
        {

            final int lminus = ((DataInputStream)src).readInt();
            if (lminus != L - 1)
            {
                throw new IllegalStateException("nspk exceeded maxNspk");
            }
            final LMSSignedPubKey[] signedPubKeys = new LMSSignedPubKey[lminus];
            if (lminus != 0)
            {
                for (int t = 0; t < signedPubKeys.length; t++)
                {
                    signedPubKeys[t] = new LMSSignedPubKey(LMSSignature.getInstance(src), LMSPublicKeyParameters.getInstance(src));
                }
            }
            final LMSSignature sig = LMSSignature.getInstance(src);

            return new HSSSignature(lminus, signedPubKeys, sig);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                return getInstance(in, L);
            }
            finally
            {
               if (in != null) {
				in.close();
			}
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src),L);
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }


    public int getlMinus1()
    {
        return this.lMinus1;
    }

    public LMSSignedPubKey[] getSignedPubKey()
    {
        return this.signedPubKey;
    }

    public LMSSignature getSignature()
    {
        return this.signature;
    }

    @Override
    public boolean equals(final Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        final HSSSignature signature1 = (HSSSignature)o;

        if (this.lMinus1 != signature1.lMinus1)
        {
            return false;
        }
        // Probably incorrect - comparing Object[] arrays with Arrays.equals

        if (this.signedPubKey.length != signature1.signedPubKey.length)
        {
            return false;
        }

        for (int t = 0; t < this.signedPubKey.length; t++)
        {
            if (!this.signedPubKey[t].equals(signature1.signedPubKey[t]))
            {
                return false;
            }
        }

        return this.signature != null ? this.signature.equals(signature1.signature) : signature1.signature == null;
    }

    @Override
    public int hashCode()
    {
        int result = this.lMinus1;
        result = 31 * result + Arrays.hashCode(this.signedPubKey);
        result = 31 * result + (this.signature != null ? this.signature.hashCode() : 0);
        return result;
    }

    @Override
	public byte[] getEncoded()
        throws IOException
    {
        final Composer composer = Composer.compose();
        composer.u32str(this.lMinus1);
        if (this.signedPubKey != null)
        {
            for (final LMSSignedPubKey sigPub : this.signedPubKey)
            {
                composer.bytes(sigPub);
            }
        }
        composer.bytes(this.signature);
        return composer.build();

    }

}
