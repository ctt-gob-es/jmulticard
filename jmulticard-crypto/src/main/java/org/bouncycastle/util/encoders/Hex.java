package org.bouncycastle.util.encoders;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Strings;

/**
 * Utility class for converting hex data to bytes and back again.
 */
public class Hex
{
    private static final HexEncoder encoder = new HexEncoder();

    public static String toHexString(
        final byte[] data)
    {
        return toHexString(data, 0, data.length);
    }

    public static String toHexString(
        final byte[] data,
        final int    off,
        final int    length)
    {
        final byte[] encoded = encode(data, off, length);
        return Strings.fromByteArray(encoded);
    }

    /**
     * encode the input data producing a Hex encoded byte array.
     *
     * @param data to encode
     * @return a byte array containing the Hex encoded data.
     */
    public static byte[] encode(
        final byte[]    data)
    {
        return encode(data, 0, data.length);
    }

    /**
     * encode the input data producing a Hex encoded byte array.
     *
     * @param data to encode
     * @param off offset
     * @param length number of bytes
     * @return a byte array containing the Hex encoded data.
     */
    public static byte[] encode(
        final byte[]    data,
        final int       off,
        final int       length)
    {
        final ByteArrayOutputStream    bOut = new ByteArrayOutputStream();

        try
        {
            encoder.encode(data, off, length, bOut);
        }
        catch (final Exception e)
        {
            throw new EncoderException("exception encoding Hex string: " + e.getMessage(), e);
        }

        return bOut.toByteArray();
    }

    /**
     * Hex encode the byte data writing it to the given output stream.
     *
     * @param data to encode
     * @param out The output stream to write to.
     * @return the number of bytes produced.
     * @throws IOException if IO error occurs.
     */
    public static int encode(
        final byte[]         data,
        final OutputStream   out)
        throws IOException
    {
        return encoder.encode(data, 0, data.length, out);
    }

    /**
     * Hex encode the byte data writing it to the given output stream.
     *
     * @param data to encode
     * @param off offset
     * @param length number of bytes
     * @param out The output stream to write to.
     * @return the number of bytes produced.
     * @throws IOException if IO error occurs.
     */
    public static int encode(
        final byte[]         data,
        final int            off,
        final int            length,
        final OutputStream   out)
        throws IOException
    {
        return encoder.encode(data, off, length, out);
    }

    /**
     * decode the Hex encoded input data. It is assumed the input data is valid.
     *
     * @param data       The source data.
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
        final byte[]    data)
    {
        final ByteArrayOutputStream    bOut = new ByteArrayOutputStream();

        try
        {
            encoder.decode(data, 0, data.length, bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding Hex data: " + e.getMessage(), e);
        }

        return bOut.toByteArray();
    }

    /**
     * decode the Hex encoded String data - whitespace will be ignored.
     *
     * @param data       The source data.
     * @return a byte array representing the decoded data.
     */
    public static byte[] decode(
        final String    data)
    {
        final ByteArrayOutputStream    bOut = new ByteArrayOutputStream();

        try
        {
            encoder.decode(data, bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
        }

        return bOut.toByteArray();
    }

    /**
     * decode the Hex encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @param data       The source data.
     * @param out The output stream to write to.
     * @return the number of bytes produced.
     * @throws IOException if IO error occurs.
     */
    public static int decode(
        final String          data,
        final OutputStream    out)
        throws IOException
    {
        return encoder.decode(data, out);
    }

    /**
     * Decode the hexadecimal-encoded string strictly i.e. any non-hexadecimal characters will be
     * considered an error.
     *
     * @param str The source data.
     * @return a byte array representing the decoded data.
     */
    public static byte[] decodeStrict(final String str)
    {
        try
        {
            return encoder.decodeStrict(str, 0, str.length());
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
        }
    }

    /**
     * Decode the hexadecimal-encoded string strictly i.e. any non-hexadecimal characters will be
     * considered an error.
     *
     * @param str The source data
     * @param off offset
     * @param len number of bytes
     * @return a byte array representing the decoded data.
     */
    public static byte[] decodeStrict(final String str, final int off, final int len)
    {
        try
        {
            return encoder.decodeStrict(str, off, len);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
        }
    }
}
