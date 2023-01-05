package org.bouncycastle.crypto.macs;

import java.util.Hashtable;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Memoable;

/**
 * HMAC implementation based on RFC2104
 *
 * H(K XOR opad, H(K XOR ipad, text))
 */
public class HMac
    implements Mac
{
    private final static byte IPAD = (byte)0x36;
    private final static byte OPAD = (byte)0x5C;

    private final Digest digest;
    private final int digestSize;
    private final int blockLength;
    private Memoable ipadState;
    private Memoable opadState;

    private final byte[] inputPad;
    private final byte[] outputBuf;

    private static Hashtable blockLengths;

    static
    {
        blockLengths = new Hashtable();

        blockLengths.put("GOST3411", Integers.valueOf(32));

        blockLengths.put("MD2", Integers.valueOf(16));
        blockLengths.put("MD4", Integers.valueOf(64));
        blockLengths.put("MD5", Integers.valueOf(64));

        blockLengths.put("RIPEMD128", Integers.valueOf(64));
        blockLengths.put("RIPEMD160", Integers.valueOf(64));

        blockLengths.put("SHA-1", Integers.valueOf(64));
        blockLengths.put("SHA-224", Integers.valueOf(64));
        blockLengths.put("SHA-256", Integers.valueOf(64));
        blockLengths.put("SHA-384", Integers.valueOf(128));
        blockLengths.put("SHA-512", Integers.valueOf(128));

        blockLengths.put("Tiger", Integers.valueOf(64));
        blockLengths.put("Whirlpool", Integers.valueOf(64));
    }

    private static int getByteLength(
        final Digest digest)
    {
        if (digest instanceof ExtendedDigest)
        {
            return ((ExtendedDigest)digest).getByteLength();
        }

        final Integer  b = (Integer)blockLengths.get(digest.getAlgorithmName());

        if (b == null)
        {
            throw new IllegalArgumentException("unknown digest passed: " + digest.getAlgorithmName());
        }

        return b.intValue();
    }

    /**
     * Base constructor for one of the standard digest algorithms that the
     * byteLength of the algorithm is know for.
     *
     * @param digest the digest.
     */
    public HMac(
        final Digest digest)
    {
        this(digest, getByteLength(digest));
    }

    private HMac(
        final Digest digest,
        final int    byteLength)
    {
        this.digest = digest;
        digestSize = digest.getDigestSize();
        blockLength = byteLength;
        inputPad = new byte[blockLength];
        outputBuf = new byte[blockLength + digestSize];
    }

    @Override
	public String getAlgorithmName()
    {
        return digest.getAlgorithmName() + "/HMAC";
    }

    public Digest getUnderlyingDigest()
    {
        return digest;
    }

    @Override
	public void init(
        final CipherParameters params)
    {
        digest.reset();

        final byte[] key = ((KeyParameter)params).getKey();
        int keyLength = key.length;

        if (keyLength > blockLength)
        {
            digest.update(key, 0, keyLength);
            digest.doFinal(inputPad, 0);

            keyLength = digestSize;
        }
        else
        {
            System.arraycopy(key, 0, inputPad, 0, keyLength);
        }

        for (int i = keyLength; i < inputPad.length; i++)
        {
            inputPad[i] = 0;
        }

        System.arraycopy(inputPad, 0, outputBuf, 0, blockLength);

        xorPad(inputPad, blockLength, IPAD);
        xorPad(outputBuf, blockLength, OPAD);

        if (digest instanceof Memoable)
        {
            opadState = ((Memoable)digest).copy();

            ((Digest)opadState).update(outputBuf, 0, blockLength);
        }

        digest.update(inputPad, 0, inputPad.length);

        if (digest instanceof Memoable)
        {
            ipadState = ((Memoable)digest).copy();
        }
    }

    @Override
	public int getMacSize()
    {
        return digestSize;
    }

    @Override
	public void update(
        final byte in)
    {
        digest.update(in);
    }

    @Override
	public void update(
        final byte[] in,
        final int inOff,
        final int len)
    {
        digest.update(in, inOff, len);
    }

    @Override
	public int doFinal(
        final byte[] out,
        final int outOff)
    {
        digest.doFinal(outputBuf, blockLength);

        if (opadState != null)
        {
            ((Memoable)digest).reset(opadState);
            digest.update(outputBuf, blockLength, digest.getDigestSize());
        }
        else
        {
            digest.update(outputBuf, 0, outputBuf.length);
        }

        final int len = digest.doFinal(out, outOff);

        for (int i = blockLength; i < outputBuf.length; i++)
        {
            outputBuf[i] = 0;
        }

        if (ipadState != null)
        {
            ((Memoable)digest).reset(ipadState);
        }
        else
        {
            digest.update(inputPad, 0, inputPad.length);
        }

        return len;
    }

    /**
     * Reset the mac generator.
     */
    @Override
	public void reset()
    {
        /*
         * reset the underlying digest.
         */
        digest.reset();

        /*
         * reinitialize the digest.
         */
        digest.update(inputPad, 0, inputPad.length);
    }

    private static void xorPad(final byte[] pad, final int len, final byte n)
    {
        for (int i = 0; i < len; ++i)
        {
            pad[i] ^= n;
        }
    }
}
