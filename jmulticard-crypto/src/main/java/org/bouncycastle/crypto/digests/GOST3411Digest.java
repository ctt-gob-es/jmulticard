package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * implementation of GOST R 34.11-94
 */
public class GOST3411Digest
    implements ExtendedDigest, Memoable
{
    private static final int    DIGEST_LENGTH = 32;

    private final byte[]   H = new byte[32], L = new byte[32],
                     M = new byte[32], Sum = new byte[32];
    private final byte[][] C = new byte[4][32];

    private final byte[]  xBuf = new byte[32];
    private int  xBufOff;
    private long byteCount;

    private final BlockCipher cipher = new GOST28147Engine();
    private byte[] sBox;

    /**
     * Standard constructor
     */
    public GOST3411Digest()
    {
        this.sBox = GOST28147Engine.getSBox("D-A");
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));

        reset();
    }

    /**
     * Constructor to allow use of a particular sbox with GOST28147
     * @param sBoxParam Box params
     * @see GOST28147Engine#getSBox(String)
     */
    public GOST3411Digest(final byte[] sBoxParam)
    {
        this.sBox = Arrays.clone(sBoxParam);
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));

        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     * @param t Digest.
     */
    public GOST3411Digest(final GOST3411Digest t)
    {
        reset(t);
    }

    @Override
	public String getAlgorithmName()
    {
        return "GOST3411";
    }

    @Override
	public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    @Override
	public void update(final byte in)
    {
        this.xBuf[this.xBufOff++] = in;
        if (this.xBufOff == this.xBuf.length)
        {
            sumByteArray(this.xBuf); // calc sum M
            processBlock(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    @Override
	public void update(final byte[] in, int inOff, int len)
    {
        while (this.xBufOff != 0 && len > 0)
        {
            update(in[inOff]);
            inOff++;
            len--;
        }

        while (len > this.xBuf.length)
        {
            System.arraycopy(in, inOff, this.xBuf, 0, this.xBuf.length);

            sumByteArray(this.xBuf); // calc sum M
            processBlock(this.xBuf, 0);
            inOff += this.xBuf.length;
            len -= this.xBuf.length;
            this.byteCount += this.xBuf.length;
        }

        // load in the remainder.
        while (len > 0)
        {
            update(in[inOff]);
            inOff++;
            len--;
        }
    }

    // (i + 1 + 4(k - 1)) = 8i + k      i = 0-3, k = 1-8
    private final byte[] K = new byte[32];

    private byte[] P(final byte[] in)
    {
        for(int k = 0; k < 8; k++)
        {
            this.K[4*k] = in[k];
            this.K[1 + 4*k] = in[ 8 + k];
            this.K[2 + 4*k] = in[16 + k];
            this.K[3 + 4*k] = in[24 + k];
        }

        return this.K;
    }

    //A (x) = (x0 ^ x1) || x3 || x2 || x1
    byte[] a = new byte[8];
    private byte[] A(final byte[] in)
    {
        for(int j=0; j<8; j++)
        {
            this.a[j]=(byte)(in[j] ^ in[j+8]);
        }

        System.arraycopy(in, 8, in, 0, 24);
        System.arraycopy(this.a, 0, in, 24, 8);

        return in;
    }

    //Encrypt function, ECB mode
    private void E(final byte[] key, final byte[] s, final int sOff, final byte[] in, final int inOff)
    {
        this.cipher.init(true, new KeyParameter(key));

        this.cipher.processBlock(in, inOff, s, sOff);
    }

    // (in:) n16||..||n1 ==> (out:) n1^n2^n3^n4^n13^n16||n16||..||n2
    short[] wS = new short[16], w_S = new short[16];

    private void fw(final byte[] in)
    {
        cpyBytesToShort(in, this.wS);
        this.w_S[15] = (short)(this.wS[0] ^ this.wS[1] ^ this.wS[2] ^ this.wS[3] ^ this.wS[12] ^ this.wS[15]);
        System.arraycopy(this.wS, 1, this.w_S, 0, 15);
        cpyShortToBytes(this.w_S, in);
    }

    // block processing
    byte[] S = new byte[32];
    byte[] U = new byte[32], V = new byte[32], W = new byte[32];

    protected void processBlock(final byte[] in, final int inOff)
    {
        System.arraycopy(in, inOff, this.M, 0, 32);

        //key step 1

        // H = h3 || h2 || h1 || h0
        // S = s3 || s2 || s1 || s0
        System.arraycopy(this.H, 0, this.U, 0, 32);
        System.arraycopy(this.M, 0, this.V, 0, 32);
        for (int j=0; j<32; j++)
        {
            this.W[j] = (byte)(this.U[j]^this.V[j]);
        }
        // Encrypt gost28147-ECB
        E(P(this.W), this.S, 0, this.H, 0); // s0 = EK0 [h0]

        //keys step 2,3,4
        for (int i=1; i<4; i++)
        {
            final byte[] tmpA = A(this.U);
            for (int j=0; j<32; j++)
            {
                this.U[j] = (byte)(tmpA[j] ^ this.C[i][j]);
            }
            this.V = A(A(this.V));
            for (int j=0; j<32; j++)
            {
                this.W[j] = (byte)(this.U[j]^this.V[j]);
            }
            // Encrypt gost28147-ECB
            E(P(this.W), this.S, i * 8, this.H, i * 8); // si = EKi [hi]
        }

        // x(M, H) = y61(H^y(M^y12(S)))
        for(int n = 0; n < 12; n++)
        {
            fw(this.S);
        }
        for(int n = 0; n < 32; n++)
        {
            this.S[n] = (byte)(this.S[n] ^ this.M[n]);
        }

        fw(this.S);

        for(int n = 0; n < 32; n++)
        {
            this.S[n] = (byte)(this.H[n] ^ this.S[n]);
        }
        for(int n = 0; n < 61; n++)
        {
            fw(this.S);
        }
        System.arraycopy(this.S, 0, this.H, 0, this.H.length);
    }

    private void finish()
    {
        Pack.longToLittleEndian(this.byteCount * 8, this.L, 0); // get length into L (byteCount * 8 = bitCount)

        while (this.xBufOff != 0)
        {
            update((byte)0);
        }

        processBlock(this.L, 0);
        processBlock(this.Sum, 0);
    }

    @Override
	public int doFinal(
        final byte[]  out,
        final int     outOff)
    {
        finish();

        System.arraycopy(this.H, 0, out, outOff, this.H.length);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables to the IV values.
     */
    private static final byte[]  C2 = {
       0x00,(byte)0xFF,0x00,(byte)0xFF,0x00,(byte)0xFF,0x00,(byte)0xFF,
       (byte)0xFF,0x00,(byte)0xFF,0x00,(byte)0xFF,0x00,(byte)0xFF,0x00,
       0x00,(byte)0xFF,(byte)0xFF,0x00,(byte)0xFF,0x00,0x00,(byte)0xFF,
       (byte)0xFF,0x00,0x00,0x00,(byte)0xFF,(byte)0xFF,0x00,(byte)0xFF};

    @Override
	public void reset()
    {
        this.byteCount = 0;
        this.xBufOff = 0;

        for(int i=0; i<this.H.length; i++)
        {
            this.H[i] = 0;  // start vector H
        }
        for(int i=0; i<this.L.length; i++)
        {
            this.L[i] = 0;
        }
        for(int i=0; i<this.M.length; i++)
        {
            this.M[i] = 0;
        }
        for(int i=0; i<this.C[1].length; i++)
        {
            this.C[1][i] = 0;  // real index C = +1 because index array with 0.
        }
        for(int i=0; i<this.C[3].length; i++)
        {
            this.C[3][i] = 0;
        }
        for(int i=0; i<this.Sum.length; i++)
        {
            this.Sum[i] = 0;
        }
        for(int i = 0; i < this.xBuf.length; i++)
        {
            this.xBuf[i] = 0;
        }

        System.arraycopy(C2, 0, this.C[2], 0, C2.length);
    }

    //  256 bitsblock modul -> (Sum + a mod (2^256))
    private void sumByteArray(final byte[] in)
    {
        int carry = 0;

        for (int i = 0; i != this.Sum.length; i++)
        {
            final int sum = (this.Sum[i] & 0xff) + (in[i] & 0xff) + carry;

            this.Sum[i] = (byte)sum;

            carry = sum >>> 8;
        }
    }

    private void cpyBytesToShort(final byte[] S, final short[] wS)
    {
        for(int i=0; i<S.length/2; i++)
        {
            wS[i] = (short)(S[i*2+1]<<8&0xFF00|S[i*2]&0xFF);
        }
    }

    private void cpyShortToBytes(final short[] wS, final byte[] S)
    {
        for(int i=0; i<S.length/2; i++)
        {
            S[i*2 + 1] = (byte)(wS[i] >> 8);
            S[i*2] = (byte)wS[i];
        }
    }

   @Override
public int getByteLength()
   {
      return 32;
   }

    @Override
	public Memoable copy()
    {
        return new GOST3411Digest(this);
    }

    @Override
	public void reset(final Memoable other)
    {
        final GOST3411Digest t = (GOST3411Digest)other;

        this.sBox = t.sBox;
        this.cipher.init(true, new ParametersWithSBox(null, this.sBox));

        reset();

        System.arraycopy(t.H, 0, this.H, 0, t.H.length);
        System.arraycopy(t.L, 0, this.L, 0, t.L.length);
        System.arraycopy(t.M, 0, this.M, 0, t.M.length);
        System.arraycopy(t.Sum, 0, this.Sum, 0, t.Sum.length);
        System.arraycopy(t.C[1], 0, this.C[1], 0, t.C[1].length);
        System.arraycopy(t.C[2], 0, this.C[2], 0, t.C[2].length);
        System.arraycopy(t.C[3], 0, this.C[3], 0, t.C[3].length);
        System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);

        this.xBufOff = t.xBufOff;
        this.byteCount = t.byteCount;
    }
}


