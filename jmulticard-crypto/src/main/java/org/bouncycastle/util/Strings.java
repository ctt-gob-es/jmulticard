package org.bouncycastle.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Vector;

import org.bouncycastle.util.encoders.UTF8;

/**
 * String utilities.
 */
public final class Strings {

    private static String LINE_SEPARATOR;

    static {
        try {
            LINE_SEPARATOR = AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
				public String run() {
                    // the easy way
                    return System.getProperty("line.separator");
                }
            });

        }
        catch (final Exception e) {
            try {
                // the harder way
                LINE_SEPARATOR = String.format("%n");
            }
            catch (final Exception ef) {
                LINE_SEPARATOR = "\n";   // we're desperate use this...
            }
        }
    }

    public static String fromUTF8ByteArray(final byte[] bytes) {
        final char[] chars = new char[bytes.length];
        final int len = UTF8.transcodeToUTF16(bytes, chars);
        if (len < 0) {
            throw new IllegalArgumentException("Invalid UTF-8 input");
        }
        return new String(chars, 0, len);
    }

    public static String fromUTF8ByteArray(final byte[] bytes, final int off, final int length) {
        final char[] chars = new char[length];
        final int len = UTF8.transcodeToUTF16(bytes, off, length, chars);
        if (len < 0) {
            throw new IllegalArgumentException("Invalid UTF-8 input");
        }
        return new String(chars, 0, len);
    }

    public static byte[] toUTF8ByteArray(final String string) {
        return toUTF8ByteArray(string.toCharArray());
    }

    public static byte[] toUTF8ByteArray(final char[] string) {
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            toUTF8ByteArray(string, bOut);
        }
        catch (final IOException e) {
            throw new IllegalStateException("cannot encode string to byte array!");
        }

        return bOut.toByteArray();
    }

    public static void toUTF8ByteArray(final char[] string,
    		                           final OutputStream sOut) throws IOException {
        final char[] c = string;
        int i = 0;

        while (i < c.length) {
            char ch = c[i];

            if (ch < 0x0080) {
                sOut.write(ch);
            }
            else if (ch < 0x0800) {
                sOut.write(0xc0 | ch >> 6);
                sOut.write(0x80 | ch & 0x3f);
            }
            // surrogate pair
            else if (ch >= 0xD800 && ch <= 0xDFFF) {
                // in error - can only happen, if the Java String class has a
                // bug.
                if (i + 1 >= c.length) {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }
                final char W1 = ch;
                ch = c[++i];
                final char W2 = ch;
                // in error - can only happen, if the Java String class has a
                // bug.
                if (W1 > 0xDBFF) {
                    throw new IllegalStateException("invalid UTF-16 codepoint");
                }
                final int codePoint = ((W1 & 0x03FF) << 10 | W2 & 0x03FF) + 0x10000;
                sOut.write(0xf0 | codePoint >> 18);
                sOut.write(0x80 | codePoint >> 12 & 0x3F);
                sOut.write(0x80 | codePoint >> 6 & 0x3F);
                sOut.write(0x80 | codePoint & 0x3F);
            }
            else {
                sOut.write(0xe0 | ch >> 12);
                sOut.write(0x80 | ch >> 6 & 0x3F);
                sOut.write(0x80 | ch & 0x3F);
            }

            i++;
        }
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(final String string) {

        boolean changed = false;
        final char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            final char ch = chars[i];
            if ('a' <= ch && 'z' >= ch) {
                changed = true;
                chars[i] = (char)(ch - 'a' + 'A');
            }
        }

        if (changed) {
            return new String(chars);
        }

        return string;
    }

    /**
     * A locale independent version of toLowerCase.
     *
     * @param string input to be converted
     * @return a US ASCII lowercase version
     */
    public static String toLowerCase(final String string) {

        boolean changed = false;
        final char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            final char ch = chars[i];
            if ('A' <= ch && 'Z' >= ch) {
                changed = true;
                chars[i] = (char)(ch - 'A' + 'a');
            }
        }

        if (changed) {
            return new String(chars);
        }

        return string;
    }

    public static byte[] toByteArray(final char[] chars) {

        final byte[] bytes = new byte[chars.length];

        for (int i = 0; i != bytes.length; i++) {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }


    public static byte[] toByteArray(final String string) {

        final byte[] bytes = new byte[string.length()];

        for (int i = 0; i != bytes.length; i++) {
            final char ch = string.charAt(i);
            bytes[i] = (byte)ch;
        }

        return bytes;
    }

    public static int toByteArray(final String s, final byte[] buf, final int off) {
        final int count = s.length();
        for (int i = 0; i < count; ++i) {
            final char c = s.charAt(i);
            buf[off + i] = (byte)c;
        }
        return count;
    }

    /**
     * Constant time string comparison.
     *
     * @param a a string.
     * @param b another string to compare to a.
     *
     * @return true if a and b represent the same string, false otherwise.
     */
    public static boolean constantTimeAreEqual(final String a, final String b)
    {
        boolean isEqual = a.length() == b.length();
        final int     len = a.length();

        for (int i = 0; i != len; i++)
        {
            isEqual &= a.charAt(i) == b.charAt(i);
        }

        return isEqual;
    }

    /**
     * Convert an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static String fromByteArray(final byte[] bytes)
    {
        return new String(asCharArray(bytes));
    }

    /**
     * Do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    public static char[] asCharArray(final byte[] bytes)
    {
        final char[] chars = new char[bytes.length];

        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }

        return chars;
    }

    public static String[] split(String input, final char delimiter)
    {
        final Vector v = new Vector();
        boolean moreTokens = true;
        String subString;

        while (moreTokens)
        {
            final int tokenLocation = input.indexOf(delimiter);
            if (tokenLocation > 0)
            {
                subString = input.substring(0, tokenLocation);
                v.addElement(subString);
                input = input.substring(tokenLocation + 1);
            }
            else
            {
                moreTokens = false;
                v.addElement(input);
            }
        }

        final String[] res = new String[v.size()];

        for (int i = 0; i != res.length; i++)
        {
            res[i] = (String)v.elementAt(i);
        }
        return res;
    }

    public static StringList newList()
    {
        return new StringListImpl();
    }

    public static String lineSeparator()
    {
        return LINE_SEPARATOR;
    }

    private static class StringListImpl
        extends ArrayList<String>
        implements StringList
    {
        @Override
		public boolean add(final String s)
        {
            return super.add(s);
        }

        @Override
		public String set(final int index, final String element)
        {
            return super.set(index, element);
        }

        @Override
		public void add(final int index, final String element)
        {
            super.add(index, element);
        }

        @Override
		public String[] toStringArray()
        {
            final String[] strs = new String[this.size()];

            for (int i = 0; i != strs.length; i++)
            {
                strs[i] = this.get(i);
            }

            return strs;
        }

        @Override
		public String[] toStringArray(final int from, final int to)
        {
            final String[] strs = new String[to - from];

            for (int i = from; i != this.size() && i != to; i++)
            {
                strs[i - from] = this.get(i);
            }

            return strs;
        }
    }


}
