package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;


/**
 * FIPS 180-2 implementation of SHA-512.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA512Digest
    extends LongDigest
{
    private static final int    DIGEST_LENGTH = 64;

    /**
     * Standard constructor
     */
    public SHA512Digest()
    {
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public SHA512Digest(final SHA512Digest t)
    {
        super(t);
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    public SHA512Digest(final byte[] encodedState)
    {
        restoreState(encodedState);
    }

    @Override
	public String getAlgorithmName()
    {
        return "SHA-512";
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
        Pack.longToBigEndian(this.H7, out, outOff + 48);
        Pack.longToBigEndian(this.H8, out, outOff + 56);

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

        /* SHA-512 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        this.H1 = 0x6a09e667f3bcc908L;
        this.H2 = 0xbb67ae8584caa73bL;
        this.H3 = 0x3c6ef372fe94f82bL;
        this.H4 = 0xa54ff53a5f1d36f1L;
        this.H5 = 0x510e527fade682d1L;
        this.H6 = 0x9b05688c2b3e6c1fL;
        this.H7 = 0x1f83d9abfb41bd6bL;
        this.H8 = 0x5be0cd19137e2179L;
    }

    @Override
	public Memoable copy()
    {
        return new SHA512Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final SHA512Digest d = (SHA512Digest)other;

        copyIn(d);
    }

    @Override
	public byte[] getEncodedState()
    {
        final byte[] encoded = new byte[getEncodedStateSize()];
        super.populateState(encoded);
        return encoded;
    }
}

