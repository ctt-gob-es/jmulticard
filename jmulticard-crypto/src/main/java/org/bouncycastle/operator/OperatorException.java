package org.bouncycastle.operator;

public class OperatorException
    extends Exception
{
    private Throwable cause;

    public OperatorException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public OperatorException(String msg)
    {
        super(msg);
    }

    @Override
	public Throwable getCause()
    {
        return cause;
    }
}
