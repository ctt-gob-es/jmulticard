package org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.RainbowPrivateKey;
import org.bouncycastle.pqc.crypto.rainbow.Layer;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;
import org.bouncycastle.pqc.jcajce.spec.RainbowPrivateKeySpec;

/**
 * The Private key in Rainbow consists of the linear affine maps L1, L2 and the
 * map F, consisting of quadratic polynomials. In this implementation, we
 * denote: L1 = A1*x + b1 L2 = A2*x + b2
 * <p>
 * The coefficients of the polynomials in F are stored in 3-dimensional arrays
 * per layer. The indices of these arrays denote the polynomial, and the
 * variables.
 * </p><p>
 * More detailed information about the private key is to be found in the paper
 * of Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable Polynomial
 * Signature Scheme. ACNS 2005: 164-175 (https://dx.doi.org/10.1007/11496137_12)
 * </p>
 */
public class BCRainbowPrivateKey
    implements PrivateKey
{
    private static final long serialVersionUID = 1L;

    // the inverse of L1
    private final short[][] A1inv;

    // translation vector element of L1
    private final short[] b1;

    // the inverse of L2
    private final short[][] A2inv;

    // translation vector of L2
    private final short[] b2;

    /*
      * components of F
      */
    private final Layer[] layers;

    // set of vinegar vars per layer.
    private final int[] vi;


    /**
     * Constructor.
     *
     * @param A1inv inverse of L1
     * @param b1 translation vector of L1
     * @param A2inv inverse of L2
     * @param b2 translation vector of L2
     * @param vi vinegar vars per layer.
     * @param layers Layers.
     */
    public BCRainbowPrivateKey(final short[][] A1inv, final short[] b1, final short[][] A2inv,
                               final short[] b2, final int[] vi, final Layer[] layers)
    {
        this.A1inv = A1inv;
        this.b1 = b1;
        this.A2inv = A2inv;
        this.b2 = b2;
        this.vi = vi;
        this.layers = layers;
    }

    /**
     * Constructor (used by the {@link RainbowKeyFactorySpi}).
     *
     * @param keySpec a {@link RainbowPrivateKeySpec}
     */
    public BCRainbowPrivateKey(final RainbowPrivateKeySpec keySpec)
    {
        this(keySpec.getInvA1(), keySpec.getB1(), keySpec.getInvA2(), keySpec
            .getB2(), keySpec.getVi(), keySpec.getLayers());
    }

    public BCRainbowPrivateKey(
        final RainbowPrivateKeyParameters params)
    {
        this(params.getInvA1(), params.getB1(), params.getInvA2(), params.getB2(), params.getVi(), params.getLayers());
    }

    /**
     * Getter for the inverse matrix of A1.
     *
     * @return the A1inv inverse
     */
    public short[][] getInvA1()
    {
        return this.A1inv;
    }

    /**
     * Getter for the translation part of the private quadratic map L1.
     *
     * @return b1 the translation part of L1
     */
    public short[] getB1()
    {
        return this.b1;
    }

    /**
     * Getter for the translation part of the private quadratic map L2.
     *
     * @return b2 the translation part of L2
     */
    public short[] getB2()
    {
        return this.b2;
    }

    /**
     * Getter for the inverse matrix of A2
     *
     * @return the A2inv
     */
    public short[][] getInvA2()
    {
        return this.A2inv;
    }

    /**
     * Returns the layers contained in the private key
     *
     * @return layers
     */
    public Layer[] getLayers()
    {
        return this.layers;
    }

    /**
     * Returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getVi()
    {
        return this.vi;
    }

    /**
     * Compare this Rainbow private key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    @Override
	public boolean equals(final Object other)
    {
        if (other == null || !(other instanceof BCRainbowPrivateKey))
        {
            return false;
        }
        final BCRainbowPrivateKey otherKey = (BCRainbowPrivateKey)other;

        boolean eq = true;
        // compare using shortcut rule ( && instead of &)
        eq = eq && RainbowUtil.equals(this.A1inv, otherKey.getInvA1());
        eq = eq && RainbowUtil.equals(this.A2inv, otherKey.getInvA2());
        eq = eq && RainbowUtil.equals(this.b1, otherKey.getB1());
        eq = eq && RainbowUtil.equals(this.b2, otherKey.getB2());
        eq = eq && Arrays.equals(this.vi, otherKey.getVi());
        if (this.layers.length != otherKey.getLayers().length)
        {
            return false;
        }
        for (int i = this.layers.length - 1; i >= 0; i--)
        {
            eq &= this.layers[i].equals(otherKey.getLayers()[i]);
        }
        return eq;
    }

    @Override
	public int hashCode()
    {
        int hash = this.layers.length;

        hash = hash * 37 + org.bouncycastle.util.Arrays.hashCode(this.A1inv);
        hash = hash * 37 + org.bouncycastle.util.Arrays.hashCode(this.b1);
        hash = hash * 37 + org.bouncycastle.util.Arrays.hashCode(this.A2inv);
        hash = hash * 37 + org.bouncycastle.util.Arrays.hashCode(this.b2);
        hash = hash * 37 + org.bouncycastle.util.Arrays.hashCode(this.vi);

        for (int i = this.layers.length - 1; i >= 0; i--)
        {
            hash = hash * 37 + this.layers[i].hashCode();
        }


        return hash;
    }

    /**
     * @return name of the algorithm - "Rainbow"
     */
    @Override
	public final String getAlgorithm()
    {
        return "Rainbow";
    }

    @Override
	public byte[] getEncoded()
    {
        final RainbowPrivateKey privateKey = new RainbowPrivateKey(this.A1inv, this.b1, this.A2inv, this.b2, this.vi, this.layers);

        PrivateKeyInfo pki;
        try
        {
            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.rainbow, DERNull.INSTANCE);
            pki = new PrivateKeyInfo(algorithmIdentifier, privateKey);
        }
        catch (final IOException e)
        {
            return null;
        }
        try
        {
            final byte[] encoded = pki.getEncoded();
            return encoded;
        }
        catch (final IOException e)
        {
            return null;
        }
    }

    @Override
	public String getFormat()
    {
        return "PKCS#8";
    }
}
