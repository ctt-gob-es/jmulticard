package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

class PEMUtil
{
    /**
     * Boundary class. Keeps track of the required header/footer pair for the
     * current PEM object.
     *
     */
    private static class Boundaries
    {
        private final String _header;
        private final String _footer;

        Boundaries(final String type) {
            this._header = "-----BEGIN " + type + "-----"; //$NON-NLS-1$ //$NON-NLS-2$
            this._footer = "-----END " + type + "-----"; //$NON-NLS-1$ //$NON-NLS-2$
        }

        public boolean isTheExpectedHeader(final String line)
        {
            return line.startsWith(_header);
        }

        public boolean isTheExpectedFooter(final String line)
        {
            return line.startsWith(_footer);
        }
    }

    private final Boundaries[] _supportedBoundaries;

    PEMUtil(final String type)
    {
        _supportedBoundaries = new Boundaries[]
        { new Boundaries(type), new Boundaries("X509 " + type), //$NON-NLS-1$
                new Boundaries("PKCS7") }; //$NON-NLS-1$
    }

    private String readLine(final InputStream in) throws IOException
    {
        int c;
        final StringBuilder l = new StringBuilder();

        do
        {
            while ((c = in.read()) != '\r' && c != '\n' && c >= 0)
            {
                l.append((char) c);
            }
        }
        while (c >= 0 && l.length() == 0);

        if (c < 0)
        {
            // make sure to return the read bytes if the end of file is encountered
            if (l.length() == 0)
            {
                return null;
            }
            return l.toString();
        }

        // make sure we parse to end of line.
        if (c == '\r')
        {
            // a '\n' may follow
            in.mark(1);
            if ((c = in.read()) == '\n')
            {
                in.mark(1);
            }

            if (c > 0)
            {
                in.reset();
            }
        }

        return l.toString();
    }

    /**
     * Returns a {@link Boundaries} object representing the passed in boundary
     * string.
     *
     * @param line the boundary string
     * @return the {@link Boundaries} object corresponding to the given boundary
     *         string or <code>null</code> if the passed in string is not a valid
     *         boundary.
     */
    private Boundaries getBoundaries(final String line)
    {
        for (final Boundaries boundary : _supportedBoundaries) {
            if (boundary.isTheExpectedHeader(line) || boundary.isTheExpectedFooter(line))
            {
                return boundary;
            }
        }

        return null;
    }

    ASN1Sequence readPEMObject(
        final InputStream in,
        final boolean     isFirst)
        throws IOException
    {
        String line;
        final StringBuilder pemBuf = new StringBuilder();

        Boundaries header = null;

        while (header == null && (line = readLine(in)) != null)
        {
            header = getBoundaries(line);
            if (header != null && !header.isTheExpectedHeader(line))
            {
                throw new IOException("malformed PEM data: found footer where header was expected"); //$NON-NLS-1$
            }
        }

        if (header == null)
        {
            if (!isFirst)
            {
                // just ignore the data
                return null;
            }
            throw new IOException("malformed PEM data: no header found"); //$NON-NLS-1$
        }

        Boundaries footer = null;

        while (footer == null && (line = readLine(in)) != null)
        {
            footer = getBoundaries(line);
            if (footer != null)
            {
                if (!header.isTheExpectedFooter(line))
                {
                    throw new IOException("malformed PEM data: header/footer mismatch"); //$NON-NLS-1$
                }
            }
            else
            {
                pemBuf.append(line);
            }
        }

        if (footer == null)
        {
            throw new IOException("malformed PEM data: no footer found"); //$NON-NLS-1$
        }

        if (pemBuf.length() != 0)
        {
            try
            {
                return ASN1Sequence.getInstance(Base64.decode(pemBuf.toString()));
            }
            catch (final Exception e)
            {
                throw new IOException("malformed PEM data encountered"); //$NON-NLS-1$
            }
        }

        return null;
    }
}
