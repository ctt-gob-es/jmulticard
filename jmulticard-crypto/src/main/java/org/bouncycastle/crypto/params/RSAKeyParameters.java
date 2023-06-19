package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class RSAKeyParameters extends AsymmetricKeyParameter {

    private static final BigInteger ONE = BigInteger.valueOf(1);

    private final BigInteger modulus;
    private final BigInteger exponent;

    public RSAKeyParameters(final boolean    isPrivate,
                            final BigInteger modulus,
                            final BigInteger exponent) {
        this(isPrivate, modulus, exponent, false);
    }

    public RSAKeyParameters(final boolean    isPrivate,
                            final BigInteger modulus,
                            final BigInteger exponent,
                            final boolean    isInternal) {
        super(isPrivate);
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }
}
