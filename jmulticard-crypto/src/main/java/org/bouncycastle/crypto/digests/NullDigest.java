package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;


public class NullDigest
    implements Digest
{
    private final OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

    @Override
	public String getAlgorithmName()
    {
        return "NULL";
    }

    @Override
	public int getDigestSize()
    {
        return bOut.size();
    }

    @Override
	public void update(final byte in)
    {
        bOut.write(in);
    }

    @Override
	public void update(final byte[] in, final int inOff, final int len)
    {
        bOut.write(in, inOff, len);
    }

    @Override
	public int doFinal(final byte[] out, final int outOff)
    {
        final int size = bOut.size();

        bOut.copy(out, outOff);

        reset();

        return size;
    }

    @Override
	public void reset()
    {
        bOut.reset();
    }

    private static class OpenByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        @Override
		public void reset()
        {
            super.reset();

            Arrays.clear(buf);
        }

        void copy(final byte[] out, final int outOff)
        {
            System.arraycopy(buf, 0, out, outOff, this.size());
        }
    }
}