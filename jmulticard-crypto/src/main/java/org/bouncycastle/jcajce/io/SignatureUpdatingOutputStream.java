package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

class SignatureUpdatingOutputStream
    extends OutputStream
{
    private final Signature sig;

    SignatureUpdatingOutputStream(final Signature sig)
    {
        this.sig = sig;
    }

    @Override
	public void write(final byte[] bytes, final int off, final int len)
        throws IOException
    {
        try
        {
            sig.update(bytes, off, len);
        }
        catch (final SignatureException e)
        {
            throw new IOException(e.getMessage());
        }
    }

    @Override
	public void write(final byte[] bytes)
        throws IOException
    {
        try
        {
            sig.update(bytes);
        }
        catch (final SignatureException e)
        {
            throw new IOException(e.getMessage());
        }
    }

    @Override
	public void write(final int b)
        throws IOException
    {
        try
        {
            sig.update((byte)b);
        }
        catch (final SignatureException e)
        {
            throw new IOException(e.getMessage());
        }
    }
}
