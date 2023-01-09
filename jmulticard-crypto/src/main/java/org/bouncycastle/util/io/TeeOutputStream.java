package org.bouncycastle.util.io;

import java.io.IOException;
import java.io.OutputStream;


/**
 * An output stream which copies anything written into it to another stream.
 */
public class TeeOutputStream
    extends OutputStream
{
    private final OutputStream output1;
    private final OutputStream output2;

    /**
     * Base constructor.
     *
     * @param output1 the output stream that is wrapped.
     * @param output2 a secondary stream that anything written to output1 is also written to.
     */
    public TeeOutputStream(final OutputStream output1, final OutputStream output2)
    {
        this.output1 = output1;
        this.output2 = output2;
    }

    @Override
	public void write(final byte[] buf)
        throws IOException
    {
        output1.write(buf);
        output2.write(buf);
    }

    @Override
	public void write(final byte[] buf, final int off, final int len)
        throws IOException
    {
        output1.write(buf, off, len);
        output2.write(buf, off, len);
    }

    @Override
	public void write(final int b)
        throws IOException
    {
        output1.write(b);
        output2.write(b);
    }

    @Override
	public void flush()
        throws IOException
    {
        output1.flush();
        output2.flush();
    }

    @Override
	public void close()
        throws IOException
    {
        output1.close();
        output2.close();
    }
}