package org.bouncycastle.crypto.digests;


import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * implementation of MD5 as outlined in "Handbook of Applied Cryptography", pages 346 - 347.
 */
public class MD5Digest
    extends GeneralDigest
    implements EncodableDigest
{
    private static final int    DIGEST_LENGTH = 16;

    private int     H1, H2, H3, H4;         // IV's

    private final int[]   X = new int[16];
    private int     xOff;

    /**
     * Standard constructor
     */
    public MD5Digest()
    {
        reset();
    }

    public MD5Digest(final byte[] encodedState)
    {
        super(encodedState);

        this.H1 = Pack.bigEndianToInt(encodedState, 16);
        this.H2 = Pack.bigEndianToInt(encodedState, 20);
        this.H3 = Pack.bigEndianToInt(encodedState, 24);
        this.H4 = Pack.bigEndianToInt(encodedState, 28);

        this.xOff = Pack.bigEndianToInt(encodedState, 32);
        for (int i = 0; i != this.xOff; i++)
        {
            this.X[i] = Pack.bigEndianToInt(encodedState, 36 + i * 4);
        }
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest
     */
    public MD5Digest(final MD5Digest t)
    {
        super(t);

        copyIn(t);
    }

    private void copyIn(final MD5Digest t)
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
        return "MD5";
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
    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;

    //
    // round 2 left rotates
    //
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;

    //
    // round 3 left rotates
    //
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;

    //
    // round 4 left rotates
    //
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;

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
     * F, G, H and I are the basic MD5 functions.
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
        return u & w | v & ~w;
    }

    private int H(
        final int u,
        final int v,
        final int w)
    {
        return u ^ v ^ w;
    }

    private int K(
        final int u,
        final int v,
        final int w)
    {
        return v ^ (u | ~w);
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
        a = rotateLeft(a + F(b, c, d) + this.X[ 0] + 0xd76aa478, S11) + b;
        d = rotateLeft(d + F(a, b, c) + this.X[ 1] + 0xe8c7b756, S12) + a;
        c = rotateLeft(c + F(d, a, b) + this.X[ 2] + 0x242070db, S13) + d;
        b = rotateLeft(b + F(c, d, a) + this.X[ 3] + 0xc1bdceee, S14) + c;
        a = rotateLeft(a + F(b, c, d) + this.X[ 4] + 0xf57c0faf, S11) + b;
        d = rotateLeft(d + F(a, b, c) + this.X[ 5] + 0x4787c62a, S12) + a;
        c = rotateLeft(c + F(d, a, b) + this.X[ 6] + 0xa8304613, S13) + d;
        b = rotateLeft(b + F(c, d, a) + this.X[ 7] + 0xfd469501, S14) + c;
        a = rotateLeft(a + F(b, c, d) + this.X[ 8] + 0x698098d8, S11) + b;
        d = rotateLeft(d + F(a, b, c) + this.X[ 9] + 0x8b44f7af, S12) + a;
        c = rotateLeft(c + F(d, a, b) + this.X[10] + 0xffff5bb1, S13) + d;
        b = rotateLeft(b + F(c, d, a) + this.X[11] + 0x895cd7be, S14) + c;
        a = rotateLeft(a + F(b, c, d) + this.X[12] + 0x6b901122, S11) + b;
        d = rotateLeft(d + F(a, b, c) + this.X[13] + 0xfd987193, S12) + a;
        c = rotateLeft(c + F(d, a, b) + this.X[14] + 0xa679438e, S13) + d;
        b = rotateLeft(b + F(c, d, a) + this.X[15] + 0x49b40821, S14) + c;

        //
        // Round 2 - G cycle, 16 times.
        //
        a = rotateLeft(a + G(b, c, d) + this.X[ 1] + 0xf61e2562, S21) + b;
        d = rotateLeft(d + G(a, b, c) + this.X[ 6] + 0xc040b340, S22) + a;
        c = rotateLeft(c + G(d, a, b) + this.X[11] + 0x265e5a51, S23) + d;
        b = rotateLeft(b + G(c, d, a) + this.X[ 0] + 0xe9b6c7aa, S24) + c;
        a = rotateLeft(a + G(b, c, d) + this.X[ 5] + 0xd62f105d, S21) + b;
        d = rotateLeft(d + G(a, b, c) + this.X[10] + 0x02441453, S22) + a;
        c = rotateLeft(c + G(d, a, b) + this.X[15] + 0xd8a1e681, S23) + d;
        b = rotateLeft(b + G(c, d, a) + this.X[ 4] + 0xe7d3fbc8, S24) + c;
        a = rotateLeft(a + G(b, c, d) + this.X[ 9] + 0x21e1cde6, S21) + b;
        d = rotateLeft(d + G(a, b, c) + this.X[14] + 0xc33707d6, S22) + a;
        c = rotateLeft(c + G(d, a, b) + this.X[ 3] + 0xf4d50d87, S23) + d;
        b = rotateLeft(b + G(c, d, a) + this.X[ 8] + 0x455a14ed, S24) + c;
        a = rotateLeft(a + G(b, c, d) + this.X[13] + 0xa9e3e905, S21) + b;
        d = rotateLeft(d + G(a, b, c) + this.X[ 2] + 0xfcefa3f8, S22) + a;
        c = rotateLeft(c + G(d, a, b) + this.X[ 7] + 0x676f02d9, S23) + d;
        b = rotateLeft(b + G(c, d, a) + this.X[12] + 0x8d2a4c8a, S24) + c;

        //
        // Round 3 - H cycle, 16 times.
        //
        a = rotateLeft(a + H(b, c, d) + this.X[ 5] + 0xfffa3942, S31) + b;
        d = rotateLeft(d + H(a, b, c) + this.X[ 8] + 0x8771f681, S32) + a;
        c = rotateLeft(c + H(d, a, b) + this.X[11] + 0x6d9d6122, S33) + d;
        b = rotateLeft(b + H(c, d, a) + this.X[14] + 0xfde5380c, S34) + c;
        a = rotateLeft(a + H(b, c, d) + this.X[ 1] + 0xa4beea44, S31) + b;
        d = rotateLeft(d + H(a, b, c) + this.X[ 4] + 0x4bdecfa9, S32) + a;
        c = rotateLeft(c + H(d, a, b) + this.X[ 7] + 0xf6bb4b60, S33) + d;
        b = rotateLeft(b + H(c, d, a) + this.X[10] + 0xbebfbc70, S34) + c;
        a = rotateLeft(a + H(b, c, d) + this.X[13] + 0x289b7ec6, S31) + b;
        d = rotateLeft(d + H(a, b, c) + this.X[ 0] + 0xeaa127fa, S32) + a;
        c = rotateLeft(c + H(d, a, b) + this.X[ 3] + 0xd4ef3085, S33) + d;
        b = rotateLeft(b + H(c, d, a) + this.X[ 6] + 0x04881d05, S34) + c;
        a = rotateLeft(a + H(b, c, d) + this.X[ 9] + 0xd9d4d039, S31) + b;
        d = rotateLeft(d + H(a, b, c) + this.X[12] + 0xe6db99e5, S32) + a;
        c = rotateLeft(c + H(d, a, b) + this.X[15] + 0x1fa27cf8, S33) + d;
        b = rotateLeft(b + H(c, d, a) + this.X[ 2] + 0xc4ac5665, S34) + c;

        //
        // Round 4 - K cycle, 16 times.
        //
        a = rotateLeft(a + K(b, c, d) + this.X[ 0] + 0xf4292244, S41) + b;
        d = rotateLeft(d + K(a, b, c) + this.X[ 7] + 0x432aff97, S42) + a;
        c = rotateLeft(c + K(d, a, b) + this.X[14] + 0xab9423a7, S43) + d;
        b = rotateLeft(b + K(c, d, a) + this.X[ 5] + 0xfc93a039, S44) + c;
        a = rotateLeft(a + K(b, c, d) + this.X[12] + 0x655b59c3, S41) + b;
        d = rotateLeft(d + K(a, b, c) + this.X[ 3] + 0x8f0ccc92, S42) + a;
        c = rotateLeft(c + K(d, a, b) + this.X[10] + 0xffeff47d, S43) + d;
        b = rotateLeft(b + K(c, d, a) + this.X[ 1] + 0x85845dd1, S44) + c;
        a = rotateLeft(a + K(b, c, d) + this.X[ 8] + 0x6fa87e4f, S41) + b;
        d = rotateLeft(d + K(a, b, c) + this.X[15] + 0xfe2ce6e0, S42) + a;
        c = rotateLeft(c + K(d, a, b) + this.X[ 6] + 0xa3014314, S43) + d;
        b = rotateLeft(b + K(c, d, a) + this.X[13] + 0x4e0811a1, S44) + c;
        a = rotateLeft(a + K(b, c, d) + this.X[ 4] + 0xf7537e82, S41) + b;
        d = rotateLeft(d + K(a, b, c) + this.X[11] + 0xbd3af235, S42) + a;
        c = rotateLeft(c + K(d, a, b) + this.X[ 2] + 0x2ad7d2bb, S43) + d;
        b = rotateLeft(b + K(c, d, a) + this.X[ 9] + 0xeb86d391, S44) + c;

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
        return new MD5Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final MD5Digest d = (MD5Digest)other;

        copyIn(d);
    }

    @Override
	public byte[] getEncodedState()
    {
        final byte[] state = new byte[36 + this.xOff * 4];

        super.populateState(state);

        Pack.intToBigEndian(this.H1, state, 16);
        Pack.intToBigEndian(this.H2, state, 20);
        Pack.intToBigEndian(this.H3, state, 24);
        Pack.intToBigEndian(this.H4, state, 28);
        Pack.intToBigEndian(this.xOff, state, 32);

        for (int i = 0; i != this.xOff; i++)
        {
            Pack.intToBigEndian(this.X[i], state, 36 + i * 4);
        }

        return state;
    }
}
