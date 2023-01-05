package org.bouncycastle.cms;

public class CMSAttributeTableGenerationException
    extends CMSRuntimeException
{
    Exception   e;

    public CMSAttributeTableGenerationException(
        String name)
    {
        super(name);
    }

    public CMSAttributeTableGenerationException(
        String name,
        Exception e)
    {
        super(name);

        this.e = e;
    }

    @Override
	public Exception getUnderlyingException()
    {
        return e;
    }
    
    @Override
	public Throwable getCause()
    {
        return e;
    }
}
