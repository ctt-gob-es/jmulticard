package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

class DigestUpdatingOutputStream
    extends OutputStream
{
    private final MessageDigest digest;

    DigestUpdatingOutputStream(final MessageDigest digest)
    {
        this.digest = digest;
    }

    @Override
	public void write(final byte[] bytes, final int off, final int len)
        throws IOException
    {
        digest.update(bytes, off, len);
    }

    @Override
	public void write(final byte[] bytes)
        throws IOException
    {
        digest.update(bytes);
    }

    @Override
	public void write(final int b)
        throws IOException
    {
        digest.update((byte)b);
    }
}
