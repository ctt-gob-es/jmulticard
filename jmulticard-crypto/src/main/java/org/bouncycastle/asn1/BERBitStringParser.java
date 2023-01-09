package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

/**
 * A parser for indefinite-length BIT STRINGs.
 */
public class BERBitStringParser
    implements ASN1BitStringParser
{
    private ASN1StreamParser _parser;

    private ConstructedBitStream _bitStream;

    BERBitStringParser(
        ASN1StreamParser parser)
    {
        _parser = parser;
    }

    @Override
	public InputStream getOctetStream() throws IOException
    {
        return _bitStream = new ConstructedBitStream(_parser, true);
    }

    @Override
	public InputStream getBitStream() throws IOException
    {
        return _bitStream = new ConstructedBitStream(_parser, false);
    }

    @Override
	public int getPadBits()
    {
        return _bitStream.getPadBits();
    }

    @Override
	public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return parse(_parser);
    }

    @Override
	public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }

    static BERBitString parse(ASN1StreamParser sp) throws IOException
    {
        ConstructedBitStream bitStream = new ConstructedBitStream(sp, false);
        byte[] data = Streams.readAll(bitStream);
        int padBits = bitStream.getPadBits();
        return new BERBitString(data, padBits);
    }
}
