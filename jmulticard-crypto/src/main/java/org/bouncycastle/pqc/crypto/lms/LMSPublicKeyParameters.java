package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class LMSPublicKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedVerifier
{
    private final LMSigParameters parameterSet;
    private final LMOtsParameters lmOtsType;
    private final byte[] I;
    private final byte[] T1;

    public LMSPublicKeyParameters(final LMSigParameters parameterSet, final LMOtsParameters lmOtsType, final byte[] T1, final byte[] I)
    {
        super(false);

        this.parameterSet = parameterSet;
        this.lmOtsType = lmOtsType;
        this.I = Arrays.clone(I);
        this.T1 = Arrays.clone(T1);
    }

    public static LMSPublicKeyParameters getInstance(final Object src)
        throws IOException
    {
        if (src instanceof LMSPublicKeyParameters)
        {
            return (LMSPublicKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            final int pubType = ((DataInputStream)src).readInt();
            final LMSigParameters lmsParameter = LMSigParameters.getParametersForType(pubType);
            final LMOtsParameters ostTypeCode = LMOtsParameters.getParametersForType(((DataInputStream)src).readInt());

            final byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);

            final byte[] T1 = new byte[lmsParameter.getM()];
            ((DataInputStream)src).readFully(T1);
            return new LMSPublicKeyParameters(lmsParameter, ostTypeCode, T1, I);
        }
        else if (src instanceof byte[])
        {

            try (InputStream in = new DataInputStream(new ByteArrayInputStream((byte[])src))) // 1.5 / 1.6 compatibility
            {
                return getInstance(in);
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    @Override
	public byte[] getEncoded()
        throws IOException
    {
        return this.toByteArray();
    }

    public LMSigParameters getSigParameters()
    {
        return parameterSet;
    }

    public LMOtsParameters getOtsParameters()
    {
        return lmOtsType;
    }

    public LMSParameters getLMSParameters()
    {
        return new LMSParameters(this.getSigParameters(), this.getOtsParameters());
    }

    public byte[] getT1()
    {
        return Arrays.clone(T1);
    }

    boolean matchesT1(final byte[] sig)
    {
        return Arrays.constantTimeAreEqual(T1, sig);
    }

    public byte[] getI()
    {
        return Arrays.clone(I);
    }

    byte[] refI()
    {
        return I;
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

        final LMSPublicKeyParameters publicKey = (LMSPublicKeyParameters)o;

        if (!parameterSet.equals(publicKey.parameterSet) || !lmOtsType.equals(publicKey.lmOtsType) || !Arrays.areEqual(I, publicKey.I))
        {
            return false;
        }
        return Arrays.areEqual(T1, publicKey.T1);
    }

    @Override
    public int hashCode()
    {
        int result = parameterSet.hashCode();
        result = 31 * result + lmOtsType.hashCode();
        result = 31 * result + Arrays.hashCode(I);
        return 31 * result + Arrays.hashCode(T1);
    }

    byte[] toByteArray()
    {
        return Composer.compose()
            .u32str(parameterSet.getType())
            .u32str(lmOtsType.getType())
            .bytes(I)
            .bytes(T1)
            .build();
    }

    @Override
	public LMSContext generateLMSContext(final byte[] signature)
    {
        try
        {
            return generateOtsContext(LMSSignature.getInstance(signature));
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("cannot parse signature: " + e.getMessage());
        }
    }

    LMSContext generateOtsContext(final LMSSignature S)
    {
        final int ots_typecode = getOtsParameters().getType();
        if (S.getOtsSignature().getType().getType() != ots_typecode)
        {
            throw new IllegalArgumentException("ots type from lsm signature does not match ots" +
                " signature type from embedded ots signature");
        }

        return new LMOtsPublicKey(LMOtsParameters.getParametersForType(ots_typecode), I,  S.getQ(), null).createOtsContext(S);
    }

    @Override
	public boolean verify(final LMSContext context)
    {
        return LMS.verifySignature(this, context);
    }
}
