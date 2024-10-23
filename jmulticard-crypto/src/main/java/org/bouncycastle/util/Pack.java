package org.bouncycastle.util;

/**
 * Utility methods for converting byte arrays into ints and longs, and back again.
 */
public abstract class Pack {

    public static short bigEndianToShort(final byte[] bs, int off) {
        int n = (bs[off] & 0xff) << 8;
        n |= bs[++off] & 0xff;
        return (short)n;
    }

    public static int bigEndianToInt(final byte[] bs, int off)
    {
        int n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= bs[++off] & 0xff;
        return n;
    }

    public static void bigEndianToInt(final byte[] bs, int off, final int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = bigEndianToInt(bs, off);
            off += 4;
        }
    }

    public static void bigEndianToInt(final byte[] bs, int off, final int[] ns, final int nsOff, final int nsLen)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            ns[nsOff + i] = bigEndianToInt(bs, off);
            off += 4;
        }
    }

    public static byte[] intToBigEndian(final int n)
    {
        final byte[] bs = new byte[4];
        intToBigEndian(n, bs, 0);
        return bs;
    }

    public static void intToBigEndian(final int n, final byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)n;
    }

    public static byte[] intToBigEndian(final int[] ns)
    {
        final byte[] bs = new byte[4 * ns.length];
        intToBigEndian(ns, bs, 0);
        return bs;
    }

    public static void intToBigEndian(final int[] ns, final byte[] bs, int off)
    {
        for (final int element : ns) {
            intToBigEndian(element, bs, off);
            off += 4;
        }
    }

    public static void intToBigEndian(final int[] ns, final int nsOff, final int nsLen, final byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            intToBigEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 4;
        }
    }

    public static long bigEndianToLong(final byte[] bs, final int off)
    {
        final int hi = bigEndianToInt(bs, off);
        final int lo = bigEndianToInt(bs, off + 4);
        return (hi & 0xffffffffL) << 32 | lo & 0xffffffffL;
    }

    public static void bigEndianToLong(final byte[] bs, int off, final long[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = bigEndianToLong(bs, off);
            off += 8;
        }
    }

    public static void bigEndianToLong(final byte[] bs, int bsOff, final long[] ns, final int nsOff, final int nsLen)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            ns[nsOff + i] = bigEndianToLong(bs, bsOff);
            bsOff += 8;
        }
    }

    public static byte[] longToBigEndian(final long n)
    {
        final byte[] bs = new byte[8];
        longToBigEndian(n, bs, 0);
        return bs;
    }

    public static void longToBigEndian(final long n, final byte[] bs, final int off)
    {
        intToBigEndian((int)(n >>> 32), bs, off);
        intToBigEndian((int)(n & 0xffffffffL), bs, off + 4);
    }

    public static byte[] longToBigEndian(final long[] ns)
    {
        final byte[] bs = new byte[8 * ns.length];
        longToBigEndian(ns, bs, 0);
        return bs;
    }

    public static void longToBigEndian(final long[] ns, final byte[] bs, int off)
    {
        for (final long element : ns) {
            longToBigEndian(element, bs, off);
            off += 8;
        }
    }

    public static void longToBigEndian(final long[] ns, final int nsOff, final int nsLen, final byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            longToBigEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 8;
        }
    }

    /**
     * @param value The number
     * @param bs    The target.
     * @param off   Position in target to start.
     * @param bytes number of bytes to write.
     *
     * @deprecated Will be removed
     */
    @Deprecated
	public static void longToBigEndian(long value, final byte[] bs, final int off, final int bytes)
    {
        for (int i = bytes - 1; i >= 0; i--)
        {
            bs[i + off] = (byte)(value & 0xff);
            value >>>= 8;
        }
    }

    public static short littleEndianToShort(final byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        return (short)n;
    }

    public static int littleEndianToInt(final byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    public static void littleEndianToInt(final byte[] bs, int off, final int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToInt(bs, off);
            off += 4;
        }
    }

    public static void littleEndianToInt(final byte[] bs, int bOff, final int[] ns, final int nOff, final int count)
    {
        for (int i = 0; i < count; ++i)
        {
            ns[nOff + i] = littleEndianToInt(bs, bOff);
            bOff += 4;
        }
    }

    public static int[] littleEndianToInt(final byte[] bs, int off, final int count)
    {
        final int[] ns = new int[count];
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToInt(bs, off);
            off += 4;
        }
        return ns;
    }

    public static byte[] shortToLittleEndian(final short n)
    {
        final byte[] bs = new byte[2];
        shortToLittleEndian(n, bs, 0);
        return bs;
    }

    public static void shortToLittleEndian(final short n, final byte[] bs, int off)
    {
        bs[off] = (byte)n;
        bs[++off] = (byte)(n >>> 8);
    }


    public static byte[] shortToBigEndian(final short n)
    {
        final byte[] r = new byte[2];
        shortToBigEndian(n, r, 0);
        return r;
    }

    public static void shortToBigEndian(final short n, final byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 8);
        bs[++off] = (byte)n;
    }


    public static byte[] intToLittleEndian(final int n)
    {
        final byte[] bs = new byte[4];
        intToLittleEndian(n, bs, 0);
        return bs;
    }

    public static void intToLittleEndian(final int n, final byte[] bs, int off)
    {
        bs[off] = (byte)n;
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    public static byte[] intToLittleEndian(final int[] ns)
    {
        final byte[] bs = new byte[4 * ns.length];
        intToLittleEndian(ns, bs, 0);
        return bs;
    }

    public static void intToLittleEndian(final int[] ns, final byte[] bs, int off)
    {
        for (final int element : ns) {
            intToLittleEndian(element, bs, off);
            off += 4;
        }
    }

    public static void intToLittleEndian(final int[] ns, final int nsOff, final int nsLen, final byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            intToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 4;
        }
    }

    public static long littleEndianToLong(final byte[] bs, final int off)
    {
        final int lo = littleEndianToInt(bs, off);
        final int hi = littleEndianToInt(bs, off + 4);
        return (hi & 0xffffffffL) << 32 | lo & 0xffffffffL;
    }

    public static void littleEndianToLong(final byte[] bs, int off, final long[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToLong(bs, off);
            off += 8;
        }
    }

    public static void littleEndianToLong(final byte[] bs, int bsOff, final long[] ns, final int nsOff, final int nsLen)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            ns[nsOff + i] = littleEndianToLong(bs, bsOff);
            bsOff += 8;
        }
    }

    public static byte[] longToLittleEndian(final long n)
    {
        final byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    public static void longToLittleEndian(final long n, final byte[] bs, final int off)
    {
        intToLittleEndian((int)(n & 0xffffffffL), bs, off);
        intToLittleEndian((int)(n >>> 32), bs, off + 4);
    }

    public static byte[] longToLittleEndian(final long[] ns)
    {
        final byte[] bs = new byte[8 * ns.length];
        longToLittleEndian(ns, bs, 0);
        return bs;
    }

    public static void longToLittleEndian(final long[] ns, final byte[] bs, int off)
    {
        for (final long element : ns) {
            longToLittleEndian(element, bs, off);
            off += 8;
        }
    }

    public static void longToLittleEndian(final long[] ns, final int nsOff, final int nsLen, final byte[] bs, int bsOff)
    {
        for (int i = 0; i < nsLen; ++i)
        {
            longToLittleEndian(ns[nsOff + i], bs, bsOff);
            bsOff += 8;
        }
    }
}
