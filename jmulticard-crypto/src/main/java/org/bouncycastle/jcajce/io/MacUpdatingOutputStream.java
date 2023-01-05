package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Mac;

class MacUpdatingOutputStream
    extends OutputStream
{
    private final Mac mac;

    MacUpdatingOutputStream(final Mac mac)
    {
        this.mac = mac;
    }

    @Override
	public void write(final byte[] bytes, final int off, final int len)
        throws IOException
    {
        mac.update(bytes, off, len);
    }

    @Override
	public void write(final byte[] bytes)
        throws IOException
    {
        mac.update(bytes);
    }

    @Override
	public void write(final int b)
        throws IOException
    {
        mac.update((byte)b);
    }
}
