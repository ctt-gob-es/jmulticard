package org.bouncycastle.crypto.digests;


import org.bouncycastle.util.Memoable;

/**
 * implementation of RIPEMD256.
 * <p>
 * <b>note:</b> this algorithm offers the same level of security as RIPEMD128.
 */
public class RIPEMD256Digest
    extends GeneralDigest
{
    private static final int DIGEST_LENGTH = 32;

    private int H0, H1, H2, H3, H4, H5, H6, H7; // IV's

    private final int[] X = new int[16];
    private int xOff;

    /**
     * Standard constructor
     */
    public RIPEMD256Digest()
    {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public RIPEMD256Digest(final RIPEMD256Digest t)
    {
        super(t);

        copyIn(t);
    }

    private void copyIn(final RIPEMD256Digest t)
    {
        super.copyIn(t);

        this.H0 = t.H0;
        this.H1 = t.H1;
        this.H2 = t.H2;
        this.H3 = t.H3;
        this.H4 = t.H4;
        this.H5 = t.H5;
        this.H6 = t.H6;
        this.H7 = t.H7;

        System.arraycopy(t.X, 0, this.X, 0, t.X.length);
        this.xOff = t.xOff;
    }

    @Override
	public String getAlgorithmName()
    {
        return "RIPEMD256";
    }

    @Override
	public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    @Override
	protected void processWord(
        final byte[] in,
        final int inOff)
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
        final long bitLength)
    {
        if (this.xOff > 14)
        {
            processBlock();
        }

        this.X[14] = (int)(bitLength & 0xffffffff);
        this.X[15] = (int)(bitLength >>> 32);
    }

    private void unpackWord(
        final int word,
        final byte[] out,
        final int outOff)
    {
        out[outOff]     = (byte)word;
        out[outOff + 1] = (byte)(word >>> 8);
        out[outOff + 2] = (byte)(word >>> 16);
        out[outOff + 3] = (byte)(word >>> 24);
    }

    @Override
	public int doFinal(
        final byte[] out,
        final int outOff)
    {
        finish();

        unpackWord(this.H0, out, outOff);
        unpackWord(this.H1, out, outOff + 4);
        unpackWord(this.H2, out, outOff + 8);
        unpackWord(this.H3, out, outOff + 12);
        unpackWord(this.H4, out, outOff + 16);
        unpackWord(this.H5, out, outOff + 20);
        unpackWord(this.H6, out, outOff + 24);
        unpackWord(this.H7, out, outOff + 28);

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

        this.H0 = 0x67452301;
        this.H1 = 0xefcdab89;
        this.H2 = 0x98badcfe;
        this.H3 = 0x10325476;
        this.H4 = 0x76543210;
        this.H5 = 0xFEDCBA98;
        this.H6 = 0x89ABCDEF;
        this.H7 = 0x01234567;

        this.xOff = 0;

        for (int i = 0; i != this.X.length; i++)
        {
            this.X[i] = 0;
        }
    }

    /*
     * rotate int x left n bits.
     */
    private int RL(
        final int x,
        final int n)
    {
        return x << n | x >>> 32 - n;
    }

    /*
     * f1,f2,f3,f4 are the basic RIPEMD128 functions.
     */

    /*
     * F
     */
    private int f1(
        final int x,
        final int y,
        final int z)
    {
        return x ^ y ^ z;
    }

    /*
     * G
     */
    private int f2(
        final int x,
        final int y,
        final int z)
    {
        return x & y | ~x & z;
    }

    /*
     * H
     */
    private int f3(
        final int x,
        final int y,
        final int z)
    {
        return (x | ~y) ^ z;
    }

    /*
     * I
     */
    private int f4(
        final int x,
        final int y,
        final int z)
    {
        return x & z | y & ~z;
    }

    private int F1(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
        return RL(a + f1(b, c, d) + x, s);
    }

    private int F2(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
        return RL(a + f2(b, c, d) + x + 0x5a827999, s);
    }

    private int F3(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
        return RL(a + f3(b, c, d) + x + 0x6ed9eba1, s);
    }

    private int F4(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
        return RL(a + f4(b, c, d) + x + 0x8f1bbcdc, s);
    }

    private int FF1(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
        return RL(a + f1(b, c, d) + x, s);
    }

    private int FF2(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
      return RL(a + f2(b, c, d) + x + 0x6d703ef3, s);
    }

    private int FF3(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
      return RL(a + f3(b, c, d) + x + 0x5c4dd124, s);
    }

    private int FF4(
        final int a,
        final int b,
        final int c,
        final int d,
        final int x,
        final int s)
    {
      return RL(a + f4(b, c, d) + x + 0x50a28be6, s);
    }

    @Override
	protected void processBlock()
    {
        int a, aa;
        int b, bb;
        int c, cc;
        int d, dd;
        int t;

        a = this.H0;
        b = this.H1;
        c = this.H2;
        d = this.H3;
        aa = this.H4;
        bb = this.H5;
        cc = this.H6;
        dd = this.H7;

        //
        // Round 1
        //

        a = F1(a, b, c, d, this.X[ 0], 11);
        d = F1(d, a, b, c, this.X[ 1], 14);
        c = F1(c, d, a, b, this.X[ 2], 15);
        b = F1(b, c, d, a, this.X[ 3], 12);
        a = F1(a, b, c, d, this.X[ 4],  5);
        d = F1(d, a, b, c, this.X[ 5],  8);
        c = F1(c, d, a, b, this.X[ 6],  7);
        b = F1(b, c, d, a, this.X[ 7],  9);
        a = F1(a, b, c, d, this.X[ 8], 11);
        d = F1(d, a, b, c, this.X[ 9], 13);
        c = F1(c, d, a, b, this.X[10], 14);
        b = F1(b, c, d, a, this.X[11], 15);
        a = F1(a, b, c, d, this.X[12],  6);
        d = F1(d, a, b, c, this.X[13],  7);
        c = F1(c, d, a, b, this.X[14],  9);
        b = F1(b, c, d, a, this.X[15],  8);

        aa = FF4(aa, bb, cc, dd, this.X[ 5],  8);
        dd = FF4(dd, aa, bb, cc, this.X[14],  9);
        cc = FF4(cc, dd, aa, bb, this.X[ 7],  9);
        bb = FF4(bb, cc, dd, aa, this.X[ 0], 11);
        aa = FF4(aa, bb, cc, dd, this.X[ 9], 13);
        dd = FF4(dd, aa, bb, cc, this.X[ 2], 15);
        cc = FF4(cc, dd, aa, bb, this.X[11], 15);
        bb = FF4(bb, cc, dd, aa, this.X[ 4],  5);
        aa = FF4(aa, bb, cc, dd, this.X[13],  7);
        dd = FF4(dd, aa, bb, cc, this.X[ 6],  7);
        cc = FF4(cc, dd, aa, bb, this.X[15],  8);
        bb = FF4(bb, cc, dd, aa, this.X[ 8], 11);
        aa = FF4(aa, bb, cc, dd, this.X[ 1], 14);
        dd = FF4(dd, aa, bb, cc, this.X[10], 14);
        cc = FF4(cc, dd, aa, bb, this.X[ 3], 12);
        bb = FF4(bb, cc, dd, aa, this.X[12],  6);

        t = a; a = aa; aa = t;

        //
        // Round 2
        //
        a = F2(a, b, c, d, this.X[ 7],  7);
        d = F2(d, a, b, c, this.X[ 4],  6);
        c = F2(c, d, a, b, this.X[13],  8);
        b = F2(b, c, d, a, this.X[ 1], 13);
        a = F2(a, b, c, d, this.X[10], 11);
        d = F2(d, a, b, c, this.X[ 6],  9);
        c = F2(c, d, a, b, this.X[15],  7);
        b = F2(b, c, d, a, this.X[ 3], 15);
        a = F2(a, b, c, d, this.X[12],  7);
        d = F2(d, a, b, c, this.X[ 0], 12);
        c = F2(c, d, a, b, this.X[ 9], 15);
        b = F2(b, c, d, a, this.X[ 5],  9);
        a = F2(a, b, c, d, this.X[ 2], 11);
        d = F2(d, a, b, c, this.X[14],  7);
        c = F2(c, d, a, b, this.X[11], 13);
        b = F2(b, c, d, a, this.X[ 8], 12);

        aa = FF3(aa, bb, cc, dd, this.X[ 6],  9);
        dd = FF3(dd, aa, bb, cc, this.X[ 11], 13);
        cc = FF3(cc, dd, aa, bb, this.X[3], 15);
        bb = FF3(bb, cc, dd, aa, this.X[ 7],  7);
        aa = FF3(aa, bb, cc, dd, this.X[0], 12);
        dd = FF3(dd, aa, bb, cc, this.X[13],  8);
        cc = FF3(cc, dd, aa, bb, this.X[5],  9);
        bb = FF3(bb, cc, dd, aa, this.X[10], 11);
        aa = FF3(aa, bb, cc, dd, this.X[14],  7);
        dd = FF3(dd, aa, bb, cc, this.X[15],  7);
        cc = FF3(cc, dd, aa, bb, this.X[ 8], 12);
        bb = FF3(bb, cc, dd, aa, this.X[12],  7);
        aa = FF3(aa, bb, cc, dd, this.X[ 4],  6);
        dd = FF3(dd, aa, bb, cc, this.X[ 9], 15);
        cc = FF3(cc, dd, aa, bb, this.X[ 1], 13);
        bb = FF3(bb, cc, dd, aa, this.X[ 2], 11);

        t = b; b = bb; bb = t;

        //
        // Round 3
        //
        a = F3(a, b, c, d, this.X[ 3], 11);
        d = F3(d, a, b, c, this.X[10], 13);
        c = F3(c, d, a, b, this.X[14],  6);
        b = F3(b, c, d, a, this.X[ 4],  7);
        a = F3(a, b, c, d, this.X[ 9], 14);
        d = F3(d, a, b, c, this.X[15],  9);
        c = F3(c, d, a, b, this.X[ 8], 13);
        b = F3(b, c, d, a, this.X[ 1], 15);
        a = F3(a, b, c, d, this.X[ 2], 14);
        d = F3(d, a, b, c, this.X[ 7],  8);
        c = F3(c, d, a, b, this.X[ 0], 13);
        b = F3(b, c, d, a, this.X[ 6],  6);
        a = F3(a, b, c, d, this.X[13],  5);
        d = F3(d, a, b, c, this.X[11], 12);
        c = F3(c, d, a, b, this.X[ 5],  7);
        b = F3(b, c, d, a, this.X[12],  5);

        aa = FF2(aa, bb, cc, dd, this.X[ 15], 9);
        dd = FF2(dd, aa, bb, cc, this.X[5], 7);
        cc = FF2(cc, dd, aa, bb, this.X[1], 15);
        bb = FF2(bb, cc, dd, aa, this.X[ 3],  11);
        aa = FF2(aa, bb, cc, dd, this.X[ 7], 8);
        dd = FF2(dd, aa, bb, cc, this.X[14],  6);
        cc = FF2(cc, dd, aa, bb, this.X[ 6], 6);
        bb = FF2(bb, cc, dd, aa, this.X[ 9], 14);
        aa = FF2(aa, bb, cc, dd, this.X[11], 12);
        dd = FF2(dd, aa, bb, cc, this.X[ 8], 13);
        cc = FF2(cc, dd, aa, bb, this.X[12],  5);
        bb = FF2(bb, cc, dd, aa, this.X[ 2], 14);
        aa = FF2(aa, bb, cc, dd, this.X[10], 13);
        dd = FF2(dd, aa, bb, cc, this.X[ 0], 13);
        cc = FF2(cc, dd, aa, bb, this.X[ 4],  7);
        bb = FF2(bb, cc, dd, aa, this.X[13],  5);

        t = c; c = cc; cc = t;

        //
        // Round 4
        //
        a = F4(a, b, c, d, this.X[ 1], 11);
        d = F4(d, a, b, c, this.X[ 9], 12);
        c = F4(c, d, a, b, this.X[11], 14);
        b = F4(b, c, d, a, this.X[10], 15);
        a = F4(a, b, c, d, this.X[ 0], 14);
        d = F4(d, a, b, c, this.X[ 8], 15);
        c = F4(c, d, a, b, this.X[12],  9);
        b = F4(b, c, d, a, this.X[ 4],  8);
        a = F4(a, b, c, d, this.X[13],  9);
        d = F4(d, a, b, c, this.X[ 3], 14);
        c = F4(c, d, a, b, this.X[ 7],  5);
        b = F4(b, c, d, a, this.X[15],  6);
        a = F4(a, b, c, d, this.X[14],  8);
        d = F4(d, a, b, c, this.X[ 5],  6);
        c = F4(c, d, a, b, this.X[ 6],  5);
        b = F4(b, c, d, a, this.X[ 2], 12);

        aa = FF1(aa, bb, cc, dd, this.X[ 8], 15);
        dd = FF1(dd, aa, bb, cc, this.X[ 6],  5);
        cc = FF1(cc, dd, aa, bb, this.X[ 4],  8);
        bb = FF1(bb, cc, dd, aa, this.X[ 1], 11);
        aa = FF1(aa, bb, cc, dd, this.X[ 3], 14);
        dd = FF1(dd, aa, bb, cc, this.X[11], 14);
        cc = FF1(cc, dd, aa, bb, this.X[15],  6);
        bb = FF1(bb, cc, dd, aa, this.X[ 0], 14);
        aa = FF1(aa, bb, cc, dd, this.X[ 5],  6);
        dd = FF1(dd, aa, bb, cc, this.X[12],  9);
        cc = FF1(cc, dd, aa, bb, this.X[ 2],  12);
        bb = FF1(bb, cc, dd, aa, this.X[13],  9);
        aa = FF1(aa, bb, cc, dd, this.X[ 9],  12);
        dd = FF1(dd, aa, bb, cc, this.X[ 7],  5);
        cc = FF1(cc, dd, aa, bb, this.X[10],  15);
        bb = FF1(bb, cc, dd, aa, this.X[14], 8);

        t = d; d = dd; dd = t;

        this.H0 += a;
        this.H1 += b;
        this.H2 += c;
        this.H3 += d;
        this.H4 += aa;
        this.H5 += bb;
        this.H6 += cc;
        this.H7 += dd;

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
        return new RIPEMD256Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final RIPEMD256Digest d = (RIPEMD256Digest)other;

        copyIn(d);
    }
}
