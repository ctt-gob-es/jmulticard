package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.MemoableResetException;
import org.bouncycastle.util.Pack;

/**
 * FIPS 180-4 implementation of SHA-512/t
 */
public class SHA512tDigest
    extends LongDigest
{
    private final int digestLength;      // non-final due to old flow analyser.

    private long  H1t, H2t, H3t, H4t, H5t, H6t, H7t, H8t;

    /**
     * Standard constructor.
     * @param bitLength Digest length.
     */
    public SHA512tDigest(final int bitLength)
    {
        if (bitLength >= 512)
        {
            throw new IllegalArgumentException("bitLength cannot be >= 512");
        }

        if (bitLength % 8 != 0)
        {
            throw new IllegalArgumentException("bitLength needs to be a multiple of 8");
        }

        if (bitLength == 384)
        {
            throw new IllegalArgumentException("bitLength cannot be 384 use SHA384 instead");
        }

        this.digestLength = bitLength / 8;

        tIvGenerate(this.digestLength * 8);

        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public SHA512tDigest(final SHA512tDigest t)
    {
        super(t);

        this.digestLength = t.digestLength;

        reset(t);
    }

    public SHA512tDigest(final byte[] encodedState)
    {
        this(readDigestLength(encodedState));
        restoreState(encodedState);
    }

    private static int readDigestLength(final byte[] encodedState)
    {
        return Pack.bigEndianToInt(encodedState, encodedState.length - 4);
    }

    @Override
	public String getAlgorithmName()
    {
        return "SHA-512/" + Integer.toString(this.digestLength * 8);
    }

    @Override
	public int getDigestSize()
    {
        return this.digestLength;
    }

    @Override
	public int doFinal(
        final byte[]  out,
        final int     outOff)
    {
        finish();

        longToBigEndian(this.H1, out, outOff, this.digestLength);
        longToBigEndian(this.H2, out, outOff + 8, this.digestLength - 8);
        longToBigEndian(this.H3, out, outOff + 16, this.digestLength - 16);
        longToBigEndian(this.H4, out, outOff + 24, this.digestLength - 24);
        longToBigEndian(this.H5, out, outOff + 32, this.digestLength - 32);
        longToBigEndian(this.H6, out, outOff + 40, this.digestLength - 40);
        longToBigEndian(this.H7, out, outOff + 48, this.digestLength - 48);
        longToBigEndian(this.H8, out, outOff + 56, this.digestLength - 56);

        reset();

        return this.digestLength;
    }

    /**
     * reset the chaining variables
     */
    @Override
	public void reset()
    {
        super.reset();

        /*
         * initial hash values use the iv generation algorithm for t.
         */
        this.H1 = this.H1t;
        this.H2 = this.H2t;
        this.H3 = this.H3t;
        this.H4 = this.H4t;
        this.H5 = this.H5t;
        this.H6 = this.H6t;
        this.H7 = this.H7t;
        this.H8 = this.H8t;
    }

    private void tIvGenerate(int bitLength)
    {
        this.H1 = 0x6a09e667f3bcc908L ^ 0xa5a5a5a5a5a5a5a5L;
        this.H2 = 0xbb67ae8584caa73bL ^ 0xa5a5a5a5a5a5a5a5L;
        this.H3 = 0x3c6ef372fe94f82bL ^ 0xa5a5a5a5a5a5a5a5L;
        this.H4 = 0xa54ff53a5f1d36f1L ^ 0xa5a5a5a5a5a5a5a5L;
        this.H5 = 0x510e527fade682d1L ^ 0xa5a5a5a5a5a5a5a5L;
        this.H6 = 0x9b05688c2b3e6c1fL ^ 0xa5a5a5a5a5a5a5a5L;
        this.H7 = 0x1f83d9abfb41bd6bL ^ 0xa5a5a5a5a5a5a5a5L;
        this.H8 = 0x5be0cd19137e2179L ^ 0xa5a5a5a5a5a5a5a5L;

        update((byte)0x53);
        update((byte)0x48);
        update((byte)0x41);
        update((byte)0x2D);
        update((byte)0x35);
        update((byte)0x31);
        update((byte)0x32);
        update((byte)0x2F);

        if (bitLength > 100)
        {
            update((byte)(bitLength / 100 + 0x30));
            bitLength = bitLength % 100;
            update((byte)(bitLength / 10 + 0x30));
            bitLength = bitLength % 10;
            update((byte)(bitLength + 0x30));
        }
        else if (bitLength > 10)
        {
            update((byte)(bitLength / 10 + 0x30));
            bitLength = bitLength % 10;
            update((byte)(bitLength + 0x30));
        }
        else
        {
            update((byte)(bitLength + 0x30));
        }

        finish();

        this.H1t = this.H1;
        this.H2t = this.H2;
        this.H3t = this.H3;
        this.H4t = this.H4;
        this.H5t = this.H5;
        this.H6t = this.H6;
        this.H7t = this.H7;
        this.H8t = this.H8;
    }

    private static void longToBigEndian(final long n, final byte[] bs, final int off, final int max)
    {
        if (max > 0)
        {
            intToBigEndian((int)(n >>> 32), bs, off, max);

            if (max > 4)
            {
                intToBigEndian((int)(n & 0xffffffffL), bs, off + 4, max - 4);
            }
        }
    }

    private static void intToBigEndian(final int n, final byte[] bs, final int off, final int max)
    {
        int num = Math.min(4, max);
        while (--num >= 0)
        {
            final int shift = 8 * (3 - num);
            bs[off + num] = (byte)(n >>> shift);
        }
    }

    @Override
	public Memoable copy()
    {
        return new SHA512tDigest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final SHA512tDigest t = (SHA512tDigest)other;

        if (this.digestLength != t.digestLength)
        {
            throw new MemoableResetException("digestLength inappropriate in other");
        }

        super.copyIn(t);

        this.H1t = t.H1t;
        this.H2t = t.H2t;
        this.H3t = t.H3t;
        this.H4t = t.H4t;
        this.H5t = t.H5t;
        this.H6t = t.H6t;
        this.H7t = t.H7t;
        this.H8t = t.H8t;
    }

    @Override
	public byte[] getEncodedState()
    {
        final int baseSize = getEncodedStateSize();
        final byte[] encoded = new byte[baseSize + 4];
        populateState(encoded);
        Pack.intToBigEndian(this.digestLength * 8, encoded, baseSize);
        return encoded;
    }

}
