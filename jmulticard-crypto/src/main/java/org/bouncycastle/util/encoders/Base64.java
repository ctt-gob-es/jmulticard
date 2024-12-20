package org.bouncycastle.util.encoders;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Strings;

/** Utility class for converting Base64 data to bytes and back again. */
public class Base64 {

    private static final Encoder encoder = new Base64Encoder();

    public static String toBase64String(final byte[] data) {
        return toBase64String(data, 0, data.length);
    }

    public static String toBase64String(final byte[] data, final int off, final int length) {
        final byte[] encoded = encode(data, off, length);
        return Strings.fromByteArray(encoded);
    }

    /** Encode the input data producing a base 64 encoded byte array.
     * @param data to encode
     * @return a byte array containing the base 64 encoded data. */
    public static byte[] encode(final byte[] data) {
        return encode(data, 0, data.length);
    }

    /** Encode the input data producing a base 64 encoded byte array.
     * @param data to encode
     * @param off offset
     * @param length number of bytes
     * @return a byte array containing the base 64 encoded data. */
    public static byte[] encode(final byte[] data, final int off, final int length) {
        final int len = encoder.getEncodedLength(length);
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

        try {
            encoder.encode(data, off, length, bOut);
        }
        catch (final Exception e) {
            throw new EncoderException("exception encoding base64 string: " + e.getMessage(), e); //$NON-NLS-1$
        }

        return bOut.toByteArray();
    }

    /** Encode the byte data to base 64 writing it to the given output stream.
     * @param data to encode
     * @param out The output stream to write to.
     * @return the number of bytes produced.
     * @throws IOException if IO error occurs. */
    public static int encode(final byte[] data, final OutputStream out) throws IOException {
        return encoder.encode(data, 0, data.length, out);
    }

    /** Encode the byte data to base 64 writing it to the given output stream.
     * @param data to encode
     * @param off offset
     * @param length number of bytes
     * @param out The output stream to write to.
     * @return the number of bytes produced.
     * @throws IOException if IO error occurs. */
    public static int encode(final byte[] data, final int off, final int length, final OutputStream out) throws IOException {
        return encoder.encode(data, off, length, out);
    }

    /** Decode the base 64 encoded input data. It is assumed the input data is valid.
     * @param data Encoded data
     * @return a byte array representing the decoded data. */
    public static byte[] decode(final byte[] data) {
        final int len = data.length / 4 * 3;
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

        try {
            encoder.decode(data, 0, data.length, bOut);
        }
        catch (final Exception e) {
            throw new DecoderException("unable to decode base64 data: " + e.getMessage(), e); //$NON-NLS-1$
        }

        return bOut.toByteArray();
    }

    /** Decode the base 64 encoded String data - whitespace will be ignored.
     * @param data Encoded data
     * @return a byte array representing the decoded data. */
    public static byte[] decode(final String data) {
        final int len = data.length() / 4 * 3;
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

        try {
            encoder.decode(data, bOut);
        }
        catch (final Exception e) {
            throw new DecoderException("unable to decode base64 string: " + e.getMessage(), e); //$NON-NLS-1$
        }

        return bOut.toByteArray();
    }

    /** Decode the base 64 encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     * @param data Encoded data
     * @param out The output stream to write to.
     * @return the number of bytes produced.
     * @throws IOException if IO error occurs. */
    public static int decode(final String data, final OutputStream out) throws IOException {
        return encoder.decode(data, out);
    }

    /** Decode to an output stream;
     * @param base64Data       The source data.
     * @param start            Start position.
     * @param length           the length.
     * @param out The output stream to write to.
     * @return the number of bytes produced. */
    public static int decode(final byte[] base64Data, final int start, final int length, final OutputStream out) {
        try {
           return encoder.decode(base64Data, start, length, out);
        }
        catch (final Exception e) {
            throw new DecoderException("unable to decode base64 data: " + e.getMessage(), e); //$NON-NLS-1$
        }
    }
}
