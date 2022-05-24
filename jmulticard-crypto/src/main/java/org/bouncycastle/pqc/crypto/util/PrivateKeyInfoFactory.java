package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.CMCEPrivateKey;
import org.bouncycastle.pqc.asn1.CMCEPublicKey;
import org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.util.Pack;

/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PrivateKeyInfoFactory
{
    private PrivateKeyInfoFactory()
    {

    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(final AsymmetricKeyParameter privateKey) throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(final AsymmetricKeyParameter privateKey, final ASN1Set attributes) throws IOException
    {
        if (privateKey instanceof QTESLAPrivateKeyParameters)
        {
            final QTESLAPrivateKeyParameters keyParams = (QTESLAPrivateKeyParameters)privateKey;

            final AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyParams.getSecret()), attributes);
        }
		if (privateKey instanceof SPHINCSPrivateKeyParameters)
        {
            final SPHINCSPrivateKeyParameters params = (SPHINCSPrivateKeyParameters)privateKey;
            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                                    new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getKeyData()));
        }
		if (privateKey instanceof NHPrivateKeyParameters)
        {
            final NHPrivateKeyParameters params = (NHPrivateKeyParameters)privateKey;

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);

            final short[] privateKeyData = params.getSecData();

            final byte[] octets = new byte[privateKeyData.length * 2];
            for (int i = 0; i != privateKeyData.length; i++)
            {
                Pack.shortToLittleEndian(privateKeyData[i], octets, i * 2);
            }

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(octets));
        }
		if (privateKey instanceof LMSPrivateKeyParameters)
        {
            final LMSPrivateKeyParameters params = (LMSPrivateKeyParameters)privateKey;

            final byte[] encoding = Composer.compose().u32str(1).bytes(params).build();
            final byte[] pubEncoding = Composer.compose().u32str(1).bytes(params.getPublicKey()).build();

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
		if (privateKey instanceof HSSPrivateKeyParameters)
        {
            final HSSPrivateKeyParameters params = (HSSPrivateKeyParameters)privateKey;

            final byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params).build();
            final byte[] pubEncoding = Composer.compose().u32str(params.getL()).bytes(params.getPublicKey().getLMSPublicKey()).build();

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
		if (privateKey instanceof SPHINCSPlusPrivateKeyParameters)
        {
            final SPHINCSPlusPrivateKeyParameters params = (SPHINCSPlusPrivateKeyParameters)privateKey;

            final byte[] encoding = params.getEncoded();
            final byte[] pubEncoding = params.getEncodedPublicKey();

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
		if (privateKey instanceof CMCEPrivateKeyParameters)
        {
            final CMCEPrivateKeyParameters params = (CMCEPrivateKeyParameters)privateKey;

            final byte[] encoding = params.getEncoded();
            //todo either make CMCEPrivateKey split the parameters from the private key or
            // (current) Make CMCEPrivateKey take parts of the private key splitted in the params

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mcElieceOidLookup(params.getParameters()));

            final CMCEPublicKey cmcePub = new CMCEPublicKey(params.reconstructPublicKey());
            final CMCEPrivateKey cmcePriv = new CMCEPrivateKey(0, params.getDelta(), params.getC(), params.getG(), params.getAlpha(), params.getS(), cmcePub);
            return new PrivateKeyInfo(algorithmIdentifier, cmcePriv, attributes);
        }
        else if (privateKey instanceof XMSSPrivateKeyParameters || privateKey instanceof XMSSMTPrivateKeyParameters)
        {
        	throw new IOException("Modificacion para JMultiCard"); //$NON-NLS-1$
        }
        else if (privateKey instanceof McElieceCCA2PrivateKeyParameters)
        {
            final McElieceCCA2PrivateKeyParameters priv = (McElieceCCA2PrivateKeyParameters)privateKey;
            final McElieceCCA2PrivateKey mcEliecePriv = new McElieceCCA2PrivateKey(priv.getN(), priv.getK(), priv.getField(), priv.getGoppaPoly(), priv.getP(), Utils.getAlgorithmIdentifier(priv.getDigest()));
            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);

            return new PrivateKeyInfo(algorithmIdentifier, mcEliecePriv);
        }
        else if (privateKey instanceof FrodoPrivateKeyParameters)
        {
            final FrodoPrivateKeyParameters params = (FrodoPrivateKeyParameters)privateKey;

            final byte[] encoding = params.getEncoded();

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.frodoOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof SABERPrivateKeyParameters)
        {
            final SABERPrivateKeyParameters params = (SABERPrivateKeyParameters)privateKey;

            final byte[] encoding = params.getEncoded();

            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.saberOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else
        {
            throw new IOException("key parameters not recognized"); //$NON-NLS-1$
        }
    }

}
