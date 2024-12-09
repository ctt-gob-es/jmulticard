package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class RSAPrivateCrtKeyParameters
    extends RSAKeyParameters
{
    private final BigInteger  e;
    private final BigInteger  p;
    private final BigInteger  q;
    private final BigInteger  dP;
    private final BigInteger  dQ;
    private final BigInteger  qInv;

    public RSAPrivateCrtKeyParameters(
         final BigInteger  modulus,
         final BigInteger  publicExponent,
         final BigInteger  privateExponent,
         final BigInteger  p,
         final BigInteger  q,
         final BigInteger  dP,
         final BigInteger  dQ,
         final BigInteger  qInv)
     {
         this(modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv, false);
     }

    public RSAPrivateCrtKeyParameters(
        final BigInteger  modulus,
        final BigInteger  publicExponent,
        final BigInteger  privateExponent,
        final BigInteger  p,
        final BigInteger  q,
        final BigInteger  dP,
        final BigInteger  dQ,
        final BigInteger  qInv,
        final boolean     isInternal)
    {
        super(true, modulus, privateExponent, isInternal);

        this.e = publicExponent;
        this.p = p;
        this.q = q;
        this.dP = dP;
        this.dQ = dQ;
        this.qInv = qInv;
    }

    public BigInteger getPublicExponent()
    {
        return this.e;
    }

    public BigInteger getP()
    {
        return this.p;
    }

    public BigInteger getQ()
    {
        return this.q;
    }

    public BigInteger getDP()
    {
        return this.dP;
    }

    public BigInteger getDQ()
    {
        return this.dQ;
    }

    public BigInteger getQInv()
    {
        return this.qInv;
    }
}
