package es.gob.jmulticard.jse.provider.ceres;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;

import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.card.fnmt.ceres.CeresPrivateKeyReference;
import es.gob.jmulticard.jse.provider.ProviderUtil;
import es.gob.jmulticard.jse.provider.SignatureAuthException;

/** Implementaci&oacute;n del SPI <code>Signature</code> para tarjeta FNMT-RCM-CERES.
 * Realiza firmas RSA con relleno PKCS#1 v1.5. Se soportan los siguientes algoritmos de firma:
 * <ul>
 *  <li>SHA1withRSA</li>
 *  <li>SHA256withRSA</li>
 *  <li>SHA384withRSA</li>
 *  <li>SHA512withRSA</li>
 * </ul>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
abstract class CeresSignatureImpl extends SignatureSpi {

    private final ByteArrayOutputStream data = new ByteArrayOutputStream();

    private Signature signatureVerifier = null;

    /** Clave privada. */
    private CeresPrivateKey privateKey = null;

    /** Algoritmo de firma. */
    private final String signatureAlgo;

    CeresSignatureImpl(final String signatureAlgorithm) {
        this.signatureAlgo = signatureAlgorithm;
    }

    @Override
    protected Object engineGetParameter(final String param) {
        throw new InvalidParameterException("Parametro no soportado"); //$NON-NLS-1$
    }

    @Override
    protected void engineInitSign(final PrivateKey prKey) throws InvalidKeyException {
        if (prKey == null) {
            throw new InvalidKeyException("La clave proporcionada es nula"); //$NON-NLS-1$
        }
        if (!(prKey instanceof CeresPrivateKey)) {
            throw new InvalidKeyException("La clave proporcionada no es de una tarjeta CERES: " + prKey.getClass().getName()); //$NON-NLS-1$
        }
        this.privateKey = (CeresPrivateKey) prKey;
        this.data.reset();
    }

    @Override
    protected void engineInitVerify(final PublicKey publicKey) throws InvalidKeyException {
        this.data.reset();
        try {
        	this.signatureVerifier = Signature.getInstance(this.signatureAlgo);
            try {
            	if (this.signatureVerifier.getProvider() instanceof CeresProvider) {
            		this.signatureVerifier = Signature.getInstance(
        				this.signatureAlgo,
        				ProviderUtil.getDefaultOtherProvider("Signature", this.signatureAlgo) //$NON-NLS-1$
    				);
            	}
            }
            catch (final NoSuchProviderException e) {
                throw new IllegalStateException(
            		"No esta instalado el proveedor por defecto de firma", e //$NON-NLS-1$
                );
            }
        }
        catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "No existe un proveedor para validar firmas con el algoritmo " + this.signatureAlgo, e //$NON-NLS-1$
            );
        }
        this.signatureVerifier.initVerify(publicKey);
    }

    @Override
    protected void engineSetParameter(final String param, final Object value) {
        throw new InvalidParameterException("Parametro no soportado"); //$NON-NLS-1$
    }

    @Override
    protected byte[] engineSign() throws SignatureException {

    	if (!(this.privateKey.getCryptoCard() instanceof Ceres)) {
    		throw new ProviderException("La clave proporcionada no se corresponde con la de una tarjeta CERES"); //$NON-NLS-1$
    	}

    	final CeresPrivateKeyReference ceresPrkRef = new CeresPrivateKeyReference(
			this.privateKey.getReference().getKeyReference(),
			this.privateKey.getReference().getKeyBitSize()
		);

    	try {
            return this.privateKey.getCryptoCard().sign(
        		this.data.toByteArray(),
        		this.signatureAlgo,
        		ceresPrkRef
    		);
        }
        catch (final CryptoCardException e) {
            throw new SignatureException(e);
        }
    	catch (final PinException e) {
			throw new SignatureAuthException(e);
		}
    }

    @Override
    protected void engineUpdate(final byte b) {
        this.data.write(b);
    }

    @Override
    protected void engineUpdate(final byte[] b, final int off, final int len) {
        this.data.write(b, off, len);
    }

    @Override
    protected boolean engineVerify(final byte[] sigBytes) throws SignatureException {
        if (this.signatureVerifier == null) {
            throw new SignatureException("La verificacion no esta inicializada"); //$NON-NLS-1$
        }
        this.signatureVerifier.update(this.data.toByteArray());
        this.data.reset();
        return this.signatureVerifier.verify(sigBytes);
    }

    /** Firma SHA1withRSA. */
    public static final class Sha1 extends CeresSignatureImpl {
        /** Constructor */
        public Sha1() {
            super("SHA1withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA256withRSA. */
    public static final class Sha256 extends CeresSignatureImpl {
        /** Constructor */
        public Sha256() {
            super("SHA256withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA384withRSA. */
    public static final class Sha384 extends CeresSignatureImpl {
        /** Constructor. */
        public Sha384() {
            super("SHA384withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA512withRSA. */
    public static final class Sha512 extends CeresSignatureImpl {
        /** Constructor. */
        public Sha512() {
            super("SHA512withRSA"); //$NON-NLS-1$
        }
    }
}