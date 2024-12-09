package org.bouncycastle.pqc.crypto.rainbow;

public class RainbowPublicKeyParameters
    extends RainbowKeyParameters
{
    private final short[][] coeffquadratic;
    private final short[][] coeffsingular;
    private final short[] coeffscalar;

    /**
     * Constructor
     *
     * @param docLength Document length.
     * @param coeffQuadratic Quadratic
     * @param coeffSingular Singular
     * @param coeffScalar Scalar
     */
    public RainbowPublicKeyParameters(final int docLength,
                                      final short[][] coeffQuadratic, final short[][] coeffSingular,
                                      final short[] coeffScalar)
    {
        super(false, docLength);

        this.coeffquadratic = coeffQuadratic;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;

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
