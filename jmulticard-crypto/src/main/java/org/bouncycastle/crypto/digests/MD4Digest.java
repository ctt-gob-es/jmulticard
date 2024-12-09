package org.bouncycastle.crypto.digests;


import org.bouncycastle.util.Memoable;

/**
 * implementation of MD4 as RFC 1320 by R. Rivest, MIT Laboratory for
 * Computer Science and RSA Data Security, Inc.
 * <p>
 * <b>NOTE</b>: This algorithm is only included for backwards compatability
 * with legacy applications, it's not secure, don't use it for anything new!
 */
public class MD4Digest
    extends GeneralDigest
{
    private static final int    DIGEST_LENGTH = 16;

    private int     H1, H2, H3, H4;         // IV's

    private final int[]   X = new int[16];
    private int     xOff;

    /**
     * Standard constructor
     */
    public MD4Digest()
    {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public MD4Digest(final MD4Digest t)
    {
        super(t);

        copyIn(t);
    }

    private void copyIn(final MD4Digest t)
    {
        super.copyIn(t);

        this.H1 = t.H1;
        this.H2 = t.H2;
        this.H3 = t.H3;
        this.H4 = t.H4;

        System.arraycopy(t.X, 0, this.X, 0, t.X.length);
        this.xOff = t.xOff;
    }

    @Override
	public String getAlgorithmName()
    {
        return "MD4";
    }

    @Override
	public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    @Override
	protected void processWord(
        final byte[]  in,
        final int     inOff)
    {
        this.X[this.xOff++] = in[inOff] & 0xff | (in[inOff + 1] & 0xff) << 8
            | (in[inOff + 2] & 0xff) << 16 | (in[inOff + 3] & 0xff) << 24;

        if (this.xOff == 16)
        {
            processBlock();
        }
    }

    @Override
	protected void processLength(
        final long    bitLength)
    {
        if (this.xOff > 14)
        {
            processBlock();
        }

        this.X[14] = (int)(bitLength & 0xffffffff);
        this.X[15] = (int)(bitLength >>> 32);
    }

    private void unpackWord(
        final int     word,
        final byte[]  out,
        final int     outOff)
    {
        out[outOff]     = (byte)word;
        out[outOff + 1] = (byte)(word >>> 8);
        out[outOff + 2] = (byte)(word >>> 16);
        out[outOff + 3] = (byte)(word >>> 24);
    }

    @Override
	public int doFinal(
        final byte[]  out,
        final int     outOff)
    {
        finish();

        unpackWord(this.H1, out, outOff);
        unpackWord(this.H2, out, outOff + 4);
        unpackWord(this.H3, out, outOff + 8);
        unpackWord(this.H4, out, outOff + 12);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables to the IV values.
     */
    @Override
	public void reset()
    {
        super.reset();

        this.H1 = 0x67452301;
        this.H2 = 0xefcdab89;
        this.H3 = 0x98badcfe;
        this.H4 = 0x10325476;

        this.xOff = 0;

        for (int i = 0; i != this.X.length; i++)
        {
            this.X[i] = 0;
        }
    }

    //
    // round 1 left rotates
    //
    private static final int S11 = 3;
    private static final int S12 = 7;
    private static final int S13 = 11;
    private static final int S14 = 19;

    //
    // round 2 left rotates
    //
    private static final int S21 = 3;
    private static final int S22 = 5;
    private static final int S23 = 9;
    private static final int S24 = 13;

    //
    // round 3 left rotates
    //
    private static final int S31 = 3;
    private static final int S32 = 9;
    private static final int S33 = 11;
    private static final int S34 = 15;

    /*
     * rotate int x left n bits.
     */
    private int rotateLeft(
        final int x,
        final int n)
    {
        return x << n | x >>> 32 - n;
    }

    /*
     * F, G, H and I are the basic MD4 functions.
     */
    private int F(
        final int u,
        final int v,
        final int w)
    {
        return u & v | ~u & w;
    }

    private int G(
        final int u,
        final int v,
        final int w)
    {
        return u & v | u & w | v & w;
    }

    private int H(
        final int u,
        final int v,
        final int w)
    {
        return u ^ v ^ w;
    }

    @Override
	protected void processBlock()
    {
        int a = this.H1;
        int b = this.H2;
        int c = this.H3;
        int d = this.H4;

        //
        // Round 1 - F cycle, 16 times.
        //
        a = rotateLeft(a + F(b, c, d) + this.X[ 0], S11);
        d = rotateLeft(d + F(a, b, c) + this.X[ 1], S12);
        c = rotateLeft(c + F(d, a, b) + this.X[ 2], S13);
        b = rotateLeft(b + F(c, d, a) + this.X[ 3], S14);
        a = rotateLeft(a + F(b, c, d) + this.X[ 4], S11);
        d = rotateLeft(d + F(a, b, c) + this.X[ 5], S12);
        c = rotateLeft(c + F(d, a, b) + this.X[ 6], S13);
        b = rotateLeft(b + F(c, d, a) + this.X[ 7], S14);
        a = rotateLeft(a + F(b, c, d) + this.X[ 8], S11);
        d = rotateLeft(d + F(a, b, c) + this.X[ 9], S12);
        c = rotateLeft(c + F(d, a, b) + this.X[10], S13);
        b = rotateLeft(b + F(c, d, a) + this.X[11], S14);
        a = rotateLeft(a + F(b, c, d) + this.X[12], S11);
        d = rotateLeft(d + F(a, b, c) + this.X[13], S12);
        c = rotateLeft(c + F(d, a, b) + this.X[14], S13);
        b = rotateLeft(b + F(c, d, a) + this.X[15], S14);

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + G(b, c, d) + this.X[ 0] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + this.X[ 4] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + this.X[ 8] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + this.X[12] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + this.X[ 1] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + this.X[ 5] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + this.X[ 9] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + this.X[13] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + this.X[ 2] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + this.X[ 6] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + this.X[10] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + this.X[14] + 0x5a827999, S24);
        a = rotateLeft(a + G(b, c, d) + this.X[ 3] + 0x5a827999, S21);
        d = rotateLeft(d + G(a, b, c) + this.X[ 7] + 0x5a827999, S22);
        c = rotateLeft(c + G(d, a, b) + this.X[11] + 0x5a827999, S23);
        b = rotateLeft(b + G(c, d, a) + this.X[15] + 0x5a827999, S24);

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + H(b, c, d) + this.X[ 0] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + this.X[ 8] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + this.X[ 4] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + this.X[12] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + this.X[ 2] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + this.X[10] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + this.X[ 6] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + this.X[14] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + this.X[ 1] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + this.X[ 9] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + this.X[ 5] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + this.X[13] + 0x6ed9eba1, S34);
        a = rotateLeft(a + H(b, c, d) + this.X[ 3] + 0x6ed9eba1, S31);
        d = rotateLeft(d + H(a, b, c) + this.X[11] + 0x6ed9eba1, S32);
        c = rotateLeft(c + H(d, a, b) + this.X[ 7] + 0x6ed9eba1, S33);
        b = rotateLeft(b + H(c, d, a) + this.X[15] + 0x6ed9eba1, S34);

        this.H1 += a;
        this.H2 += b;
        this.H3 += c;
        this.H4 += d;

        //
        // reset the offset and clean out the word buffer.
        //
        this.xOff = 0;
        for (int i = 0; i != this.X.length; i++)
        {
            this.X[i] = 0;
        }
    }

    @Override
	public Memoable copy()
    {
        return new MD4Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final MD4Digest d = (MD4Digest)other;

        copyIn(d);
    }
}
