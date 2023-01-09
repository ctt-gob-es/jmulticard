package org.bouncycastle.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class BcDigestCalculatorProvider
    implements DigestCalculatorProvider
{
    private final BcDigestProvider digestProvider = BcDefaultDigestProvider.INSTANCE;

    @Override
	public DigestCalculator get(final AlgorithmIdentifier algorithm)
        throws OperatorCreationException
    {
        final Digest dig = digestProvider.get(algorithm);

        final DigestOutputStream stream = new DigestOutputStream(dig);

        return new DigestCalculator()
        {
            @Override
			public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return algorithm;
            }

            @Override
			public OutputStream getOutputStream()
            {
                return stream;
            }

            @Override
			public byte[] getDigest()
            {
                return stream.getDigest();
            }
        };
    }

    private static class DigestOutputStream
        extends OutputStream
    {
        private final Digest dig;

        DigestOutputStream(final Digest dig)
        {
            this.dig = dig;
        }

        @Override
		public void write(final byte[] bytes, final int off, final int len)
            throws IOException
        {
            dig.update(bytes, off, len);
        }

        @Override
		public void write(final byte[] bytes)
            throws IOException
        {
            dig.update(bytes, 0, bytes.length);
        }

        @Override
		public void write(final int b)
            throws IOException
        {
            dig.update((byte)b);
        }

        byte[] getDigest()
        {
            final byte[] d = new byte[dig.getDigestSize()];

            dig.doFinal(d, 0);

            return d;
        }
    }
}