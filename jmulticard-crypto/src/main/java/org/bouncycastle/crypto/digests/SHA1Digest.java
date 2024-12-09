package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * implementation of SHA-1 as outlined in "Handbook of Applied Cryptography", pages 346 - 349.
 *
 * It is interesting to ponder why the, apart from the extra IV, the other difference here from MD5
 * is the "endianness" of the word processing!
 */
public class SHA1Digest
    extends GeneralDigest
    implements EncodableDigest
{
    private static final int    DIGEST_LENGTH = 20;

    private int     H1, H2, H3, H4, H5;

    private final int[]   X = new int[80];
    private int     xOff;

    /**
     * Standard constructor
     */
    public SHA1Digest()
    {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public SHA1Digest(final SHA1Digest t)
    {
        super(t);

        copyIn(t);
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    public SHA1Digest(final byte[] encodedState)
    {
        super(encodedState);

        this.H1 = Pack.bigEndianToInt(encodedState, 16);
        this.H2 = Pack.bigEndianToInt(encodedState, 20);
        this.H3 = Pack.bigEndianToInt(encodedState, 24);
        this.H4 = Pack.bigEndianToInt(encodedState, 28);
        this.H5 = Pack.bigEndianToInt(encodedState, 32);

        this.xOff = Pack.bigEndianToInt(encodedState, 36);
        for (int i = 0; i != this.xOff; i++)
        {
            this.X[i] = Pack.bigEndianToInt(encodedState, 40 + i * 4);
        }
    }

    private void copyIn(final SHA1Digest t)
    {
        this.H1 = t.H1;
        this.H2 = t.H2;
        this.H3 = t.H3;
        this.H4 = t.H4;
        this.H5 = t.H5;

        System.arraycopy(t.X, 0, this.X, 0, t.X.length);
        this.xOff = t.xOff;
    }

    @Override
	public String getAlgorithmName()
    {
        return "SHA-1";
    }

    @Override
	public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    @Override
	protected void processWord(
        final byte[]  in,
        int     inOff)
    {
        // Note: Inlined for performance
//        X[xOff] = Pack.bigEndianToInt(in, inOff);
        int n = in[  inOff] << 24;
        n |= (in[++inOff] & 0xff) << 16;
        n |= (in[++inOff] & 0xff) << 8;
        n |= in[++inOff] & 0xff;
        this.X[this.xOff] = n;

        if (++this.xOff == 16)
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

        this.X[14] = (int)(bitLength >>> 32);
        this.X[15] = (int)bitLength;
    }

    @Override
	public int doFinal(
        final byte[]  out,
        final int     outOff)
    {
        finish();

        Pack.intToBigEndian(this.H1, out, outOff);
        Pack.intToBigEndian(this.H2, out, outOff + 4);
        Pack.intToBigEndian(this.H3, out, outOff + 8);
        Pack.intToBigEndian(this.H4, out, outOff + 12);
        Pack.intToBigEndian(this.H5, out, outOff + 16);

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

        this.H1 = 0x67452301;
        this.H2 = 0xefcdab89;
        this.H3 = 0x98badcfe;
        this.H4 = 0x10325476;
        this.H5 = 0xc3d2e1f0;

        this.xOff = 0;
        for (int i = 0; i != this.X.length; i++)
        {
            this.X[i] = 0;
        }
    }

    //
    // Additive constants
    //
    private static final int    Y1 = 0x5a827999;
    private static final int    Y2 = 0x6ed9eba1;
    private static final int    Y3 = 0x8f1bbcdc;
    private static final int    Y4 = 0xca62c1d6;

    private int f(
        final int    u,
        final int    v,
        final int    w)
    {
        return u & v | ~u & w;
    }

    private int h(
        final int    u,
        final int    v,
        final int    w)
    {
        return u ^ v ^ w;
    }

    private int g(
        final int    u,
        final int    v,
        final int    w)
    {
        return u & v | u & w | v & w;
    }

    @Override
	protected void processBlock()
    {
        //
        // expand 16 word block into 80 word block.
        //
        for (int i = 16; i < 80; i++)
        {
            final int t = this.X[i - 3] ^ this.X[i - 8] ^ this.X[i - 14] ^ this.X[i - 16];
            this.X[i] = t << 1 | t >>> 31;
        }

        //
        // set up working variables.
        //
        int     A = this.H1;
        int     B = this.H2;
        int     C = this.H3;
        int     D = this.H4;
        int     E = this.H5;

        //
        // round 1
        //
        int idx = 0;

        for (int j = 0; j < 4; j++)
        {
            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + f(B, C, D) + this.X[idx++] + Y1;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + f(A, B, C) + this.X[idx++] + Y1;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + f(E, A, B) + this.X[idx++] + Y1;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + f(D, E, A) + this.X[idx++] + Y1;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + f(C, D, E) + this.X[idx++] + Y1;
            C = C << 30 | C >>> 2;
        }

        //
        // round 2
        //
        for (int j = 0; j < 4; j++)
        {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + h(B, C, D) + this.X[idx++] + Y2;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + h(A, B, C) + this.X[idx++] + Y2;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + h(E, A, B) + this.X[idx++] + Y2;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + h(D, E, A) + this.X[idx++] + Y2;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + h(C, D, E) + this.X[idx++] + Y2;
            C = C << 30 | C >>> 2;
        }

        //
        // round 3
        //
        for (int j = 0; j < 4; j++)
        {
            // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + g(B, C, D) + this.X[idx++] + Y3;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + g(A, B, C) + this.X[idx++] + Y3;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + g(E, A, B) + this.X[idx++] + Y3;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + g(D, E, A) + this.X[idx++] + Y3;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + g(C, D, E) + this.X[idx++] + Y3;
            C = C << 30 | C >>> 2;
        }

        //
        // round 4
        //
        for (int j = 0; j <= 3; j++)
        {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | A >>> 27) + h(B, C, D) + this.X[idx++] + Y4;
            B = B << 30 | B >>> 2;

            D += (E << 5 | E >>> 27) + h(A, B, C) + this.X[idx++] + Y4;
            A = A << 30 | A >>> 2;

            C += (D << 5 | D >>> 27) + h(E, A, B) + this.X[idx++] + Y4;
            E = E << 30 | E >>> 2;

            B += (C << 5 | C >>> 27) + h(D, E, A) + this.X[idx++] + Y4;
            D = D << 30 | D >>> 2;

            A += (B << 5 | B >>> 27) + h(C, D, E) + this.X[idx++] + Y4;
            C = C << 30 | C >>> 2;
        }


        this.H1 += A;
        this.H2 += B;
        this.H3 += C;
        this.H4 += D;
        this.H5 += E;

        //
        // reset start of the buffer.
        //
        this.xOff = 0;
        for (int i = 0; i < 16; i++)
        {
            this.X[i] = 0;
        }
    }

    @Override
	public Memoable copy()
    {
        return new SHA1Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final SHA1Digest d = (SHA1Digest)other;

        super.copyIn(d);
        copyIn(d);
    }

    @Override
	public byte[] getEncodedState()
    {
        final byte[] state = new byte[40 + this.xOff * 4];

        super.populateState(state);

        Pack.intToBigEndian(this.H1, state, 16);
        Pack.intToBigEndian(this.H2, state, 20);
        Pack.intToBigEndian(this.H3, state, 24);
        Pack.intToBigEndian(this.H4, state, 28);
        Pack.intToBigEndian(this.H5, state, 32);
        Pack.intToBigEndian(this.xOff, state, 36);

        for (int i = 0; i != this.xOff; i++)
        {
            Pack.intToBigEndian(this.X[i], state, 40 + i * 4);
        }

        return state;
    }
}




