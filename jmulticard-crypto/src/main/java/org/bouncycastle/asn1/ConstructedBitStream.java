package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

class ConstructedBitStream extends InputStream {
    private final ASN1StreamParser _parser;
    private final boolean _octetAligned;

    private boolean                _first = true;
    private int                    _padBits = 0;

    private ASN1BitStringParser    _currentParser;
    private InputStream            _currentStream;

    ConstructedBitStream(final ASN1StreamParser parser, final boolean octetAligned) {
        _parser = parser;
        _octetAligned = octetAligned;
    }

    int getPadBits() {
        return _padBits;
    }

    @Override
	public int read(final byte[] b, final int off, final int len) throws IOException {
        if (_currentStream == null) {
            if (!_first) {
                return -1;
            }

            _currentParser = getNextParser();
            if (_currentParser == null) {
                return -1;
            }

            _first = false;
            _currentStream = _currentParser.getBitStream();
        }

        int totalRead = 0;

        for (;;) {
            final int numRead = _currentStream.read(b, off + totalRead, len - totalRead);

            if (numRead >= 0) {
                totalRead += numRead;

                if (totalRead == len) {
                    return totalRead;
                }
            }
            else {
                _padBits = _currentParser.getPadBits();
                _currentParser = getNextParser();
                if (_currentParser == null) {
                    _currentStream = null;
                    return totalRead < 1 ? -1 : totalRead;
                }

                _currentStream = _currentParser.getBitStream();
            }
        }
    }

    @Override
	public int read()
        throws IOException
    {
        if (_currentStream == null)
        {
            if (!_first)
            {
                return -1;
            }

            _currentParser = getNextParser();
            if (_currentParser == null)
            {
                return -1;
            }

            _first = false;
            _currentStream = _currentParser.getBitStream();
        }

        for (;;)
        {
            final int b = _currentStream.read();

            if (b >= 0)
            {
                return b;
            }

            _padBits = _currentParser.getPadBits();
            _currentParser = getNextParser();
            if (_currentParser == null)
            {
                _currentStream = null;
                return -1;
            }

            _currentStream = _currentParser.getBitStream();
        }
    }

    private ASN1BitStringParser getNextParser() throws IOException
    {
        final ASN1Encodable asn1Obj = _parser.readObject();
        if (asn1Obj == null)
        {
            if (_octetAligned && _padBits != 0)
            {
                throw new IOException("expected octet-aligned bitstring, but found padBits: " + _padBits);
            }

            return null;
        }

        if (asn1Obj instanceof ASN1BitStringParser)
        {
            if (_padBits != 0)
            {
                throw new IOException("only the last nested bitstring can have padding");
            }

            return (ASN1BitStringParser)asn1Obj;
        }

        throw new IOException("unknown object encountered: " + asn1Obj.getClass());
    }
}
