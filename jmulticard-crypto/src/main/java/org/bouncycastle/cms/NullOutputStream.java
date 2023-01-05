/**
 *
 */
package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

class NullOutputStream
    extends OutputStream
{
    @Override
	public void write(final byte[] buf)
        throws IOException
    {
        // do nothing
    }

    @Override
	public void write(final byte[] buf, final int off, final int len)
        throws IOException
    {
        // do nothing
    }

    @Override
	public void write(final int b) throws IOException
    {
        // do nothing
    }
}