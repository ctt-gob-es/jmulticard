package org.bouncycastle.pqc.jcajce.spec;


import java.security.spec.KeySpec;

/**
 * This class provides a specification for a RainbowSignature public key.
 *
 * @see KeySpec
 */
public class RainbowPublicKeySpec
    implements KeySpec
{
    private final short[][] coeffquadratic;
    private final short[][] coeffsingular;
    private final short[] coeffscalar;
    private final int docLength; // length of possible document to sign

    /**
     * Constructor
     *
     * @param docLength Length.
     * @param coeffquadratic Quadratic.
     * @param coeffSingular Singular.
     * @param coeffScalar Scalar.
     */
    public RainbowPublicKeySpec(final int docLength,
                                final short[][] coeffquadratic, final short[][] coeffSingular,
                                final short[] coeffScalar)
    {
        this.docLength = docLength;
        this.coeffquadratic = coeffquadratic;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;
    }

    /**
     * @return the docLength
     */
    public int getDocLength()
    {
        return this.docLength;
    }

    /**
     * @return the coeffquadratic
     */
    public short[][] getCoeffQuadratic()
    {
        return this.coeffquadratic;
    }

    /**
     * @return the coeffsingular
     */
    public short[][] getCoeffSingular()
    {
        return this.coeffsingular;
    }

    /**
     * @return the coeffscalar
     */
    public short[] getCoeffScalar()
    {
        return this.coeffscalar;
    }
}
