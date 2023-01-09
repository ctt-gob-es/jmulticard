package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.util.ComputeInField;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/**
 * It implements the sign and verify functions for the Rainbow Signature Scheme.
 * Here the message, which has to be signed, is updated. The use of
 * different hash functions is possible.
 * <p>
 * Detailed information about the signature and the verify-method is to be found
 * in the paper of Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable
 * Polynomial Signature Scheme. ACNS 2005: 164-175
 * (https://dx.doi.org/10.1007/11496137_12)
 */
public class RainbowSigner
    implements MessageSigner
{
    private static final int MAXITS = 65536;

    // Source of randomness
    private SecureRandom random;

    // The length of a document that can be signed with the privKey
    int signableDocumentLength;

    // Container for the oil and vinegar variables of all the layers
    private short[] x;

    private final ComputeInField cf = new ComputeInField();

    RainbowKeyParameters key;

    @Override
	public void init(final boolean forSigning,
                     final CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                final ParametersWithRandom rParam = (ParametersWithRandom)param;

                random = rParam.getRandom();
                key = (RainbowPrivateKeyParameters)rParam.getParameters();

            }
            else
            {

                random = CryptoServicesRegistrar.getSecureRandom();
                key = (RainbowPrivateKeyParameters)param;
            }
        }
        else
        {
            key = (RainbowPublicKeyParameters)param;
        }

        signableDocumentLength = key.getDocLength();
    }


    /**
     * initial operations before solving the Linear equation system.
     *
     * @param layer the current layer for which a LES is to be solved.
     * @param msg   the message that should be signed.
     * @return Y_ the modified document needed for solving LES, (Y_ =
     * A1^{-1}*(Y-b1)) linear map L1 = A1 x + b1.
     */
    private short[] initSign(final Layer[] layer, final short[] msg)
    {

        /* preparation: Modifies the document with the inverse of L1 */
        // tmp = Y - b1:
        short[] tmpVec = new short[msg.length];

        tmpVec = cf.addVect(((RainbowPrivateKeyParameters)key).getB1(), msg);

        // Y_ = A1^{-1} * (Y - b1) :
        final short[] Y_ = cf.multiplyMatrix(((RainbowPrivateKeyParameters)key).getInvA1(), tmpVec);

        /* generates the vinegar vars of the first layer at random */
        for (int i = 0; i < layer[0].getVi(); i++)
        {
            x[i] = (short)random.nextInt();
            x[i] = (short)(x[i] & GF2Field.MASK);
        }

        return Y_;
    }

    /**
     * This function signs the message that has been updated, making use of the
     * private key.
     * <p>
     * For computing the signature, L1 and L2 are needed, as well as LES should
     * be solved for each layer in order to find the Oil-variables in the layer.
     * <p>
     * The Vinegar-variables of the first layer are random generated.
     *
     * @param message the message
     * @return the signature of the message.
     */
    @Override
	public byte[] generateSignature(final byte[] message)
    {
        final Layer[] layer = ((RainbowPrivateKeyParameters)key).getLayers();
        final int numberOfLayers = layer.length;

        x = new short[((RainbowPrivateKeyParameters)key).getInvA2().length]; // all variables

        short[] Y_; // modified document
        short[] y_i; // part of Y_ each polynomial
        int counter; // index of the current part of the doc

        short[] solVec; // the solution of LES pro layer
        short[] tmpVec;

        // the signature as an array of shorts:
        short[] signature;
        // the signature as a byte-array:
        final byte[] S = new byte[layer[numberOfLayers - 1].getViNext()];

        final short[] msgHashVals = makeMessageRepresentative(message);
        int itCount = 0;

        // shows if an exception is caught
        boolean ok;
        do
        {
            ok = true;
            counter = 0;
            try
            {
                Y_ = initSign(layer, msgHashVals);

                for (int i = 0; i < numberOfLayers; i++)
                {

                    y_i = new short[layer[i].getOi()];
                    solVec = new short[layer[i].getOi()]; // solution of LES

                    /* copy oi elements of Y_ into y_i */
                    for (int k = 0; k < layer[i].getOi(); k++)
                    {
                        y_i[k] = Y_[counter];
                        counter++; // current index of Y_
                    }

                    /*
                     * plug in the vars of the previous layer in order to get
                     * the vars of the current layer
                     */
                    solVec = cf.solveEquation(layer[i].plugInVinegars(x), y_i);

                    if (solVec == null)
                    { // LES is not solveable
                        throw new Exception("LES is not solveable!");
                    }

                    /* copy the new vars into the x-array */
                    for (int j = 0; j < solVec.length; j++)
                    {
                        x[layer[i].getVi() + j] = solVec[j];
                    }
                }

                /* apply the inverse of L2: (signature = A2^{-1}*(b2+x)) */
                tmpVec = cf.addVect(((RainbowPrivateKeyParameters)key).getB2(), x);
                signature = cf.multiplyMatrix(((RainbowPrivateKeyParameters)key).getInvA2(), tmpVec);

                /* cast signature from short[] to byte[] */
                for (int i = 0; i < S.length; i++)
                {
                    S[i] = (byte)signature[i];
                }
            }
            catch (final Exception se)
            {
                // if one of the LESs was not solveable - sign again
                ok = false;
            }
        }
        while (!ok && ++itCount < MAXITS);
        /* return the signature in bytes */

        if (itCount == MAXITS)
        {
            throw new IllegalStateException("unable to generate signature - LES not solvable");
        }

        return S;
    }

    /**
     * This function verifies the signature of the message that has been
     * updated, with the aid of the public key.
     *
     * @param message   the message
     * @param signature the signature of the message
     * @return true if the signature has been verified, false otherwise.
     */
    @Override
	public boolean verifySignature(final byte[] message, final byte[] signature)
    {
        final short[] sigInt = new short[signature.length];
        short tmp;

        for (int i = 0; i < signature.length; i++)
        {
            tmp = signature[i];
            tmp &= (short)0xff;
            sigInt[i] = tmp;
        }

        final short[] msgHashVal = makeMessageRepresentative(message);

        // verify
        final short[] verificationResult = verifySignatureIntern(sigInt);

        // compare
        boolean verified = true;
        if (msgHashVal.length != verificationResult.length)
        {
            return false;
        }
        for (int i = 0; i < msgHashVal.length; i++)
        {
            verified = verified && msgHashVal[i] == verificationResult[i];
        }

        return verified;
    }

    /**
     * Signature verification using public key
     *
     * @param signature vector of dimension n
     * @return document hash of length n - v1
     */
    private short[] verifySignatureIntern(final short[] signature)
    {

        final short[][] coeff_quadratic = ((RainbowPublicKeyParameters)key).getCoeffQuadratic();
        final short[][] coeff_singular = ((RainbowPublicKeyParameters)key).getCoeffSingular();
        final short[] coeff_scalar = ((RainbowPublicKeyParameters)key).getCoeffScalar();

        final short[] rslt = new short[coeff_quadratic.length];// n - v1
        final int n = coeff_singular[0].length;
        int offset = 0; // array position
        short tmp = 0; // for scalar

        for (int p = 0; p < coeff_quadratic.length; p++)
        { // no of polynomials
            offset = 0;
            for (int x = 0; x < n; x++)
            {
                // calculate quadratic terms
                for (int y = x; y < n; y++)
                {
                    tmp = GF2Field.multElem(coeff_quadratic[p][offset],
                        GF2Field.multElem(signature[x], signature[y]));
                    rslt[p] = GF2Field.addElem(rslt[p], tmp);
                    offset++;
                }
                // calculate singular terms
                tmp = GF2Field.multElem(coeff_singular[p][x], signature[x]);
                rslt[p] = GF2Field.addElem(rslt[p], tmp);
            }
            // add scalar
            rslt[p] = GF2Field.addElem(rslt[p], coeff_scalar[p]);
        }

        return rslt;
    }

    /**
     * This function creates the representative of the message which gets signed
     * or verified.
     *
     * @param message the message
     * @return message representative
     */
    private short[] makeMessageRepresentative(final byte[] message)
    {
        // the message representative
        final short[] output = new short[signableDocumentLength];

        int h = 0;
        int i = 0;
        do
        {
            if (i >= message.length)
            {
                break;
            }
            output[i] = message[h];
            output[i] &= (short)0xff;
            h++;
            i++;
        }
        while (i < output.length);

        return output;
    }
}
