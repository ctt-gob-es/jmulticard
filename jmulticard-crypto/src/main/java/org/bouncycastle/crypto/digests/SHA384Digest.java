package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;


/**
 * FIPS 180-2 implementation of SHA-384.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA384Digest
    extends LongDigest
{
    private static final int    DIGEST_LENGTH = 48;

    /**
     * Standard constructor
     */
    public SHA384Digest()
    {
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public SHA384Digest(final SHA384Digest t)
    {
        super(t);
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    public SHA384Digest(final byte[] encodedState)
    {
        restoreState(encodedState);
    }

    @Override
	public String getAlgorithmName()
    {
        return "SHA-384";
    }

    @Override
	public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    @Override
	public int doFinal(
        final byte[]  out,
        final int     outOff)
    {
        finish();

        Pack.longToBigEndian(this.H1, out, outOff);
        Pack.longToBigEndian(this.H2, out, outOff + 8);
        Pack.longToBigEndian(this.H3, out, outOff + 16);
        Pack.longToBigEndian(this.H4, out, outOff + 24);
        Pack.longToBigEndian(this.H5, out, outOff + 32);
        Pack.longToBigEndian(this.H6, out, outOff + 40);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables
     */
    @Override
	public void reset()
    {
        super.reset();

        /* SHA-384 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the 9th through 16th prime numbers
         */
        this.H1 = 0xcbbb9d5dc1059ed8l;
        this.H2 = 0x629a292a367cd507l;
        this.H3 = 0x9159015a3070dd17l;
        this.H4 = 0x152fecd8f70e5939l;
        this.H5 = 0x67332667ffc00b31l;
        this.H6 = 0x8eb44a8768581511l;
        this.H7 = 0xdb0c2e0d64f98fa7l;
        this.H8 = 0x47b5481dbefa4fa4l;
    }

    @Override
	public Memoable copy()
    {
        return new SHA384Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final SHA384Digest d = (SHA384Digest)other;

        super.copyIn(d);
    }

    @Override
	public byte[] getEncodedState()
    {
        final byte[] encoded = new byte[getEncodedStateSize()];
        super.populateState(encoded);
        return encoded;
    }
}
