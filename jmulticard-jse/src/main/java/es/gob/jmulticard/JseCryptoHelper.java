/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.spongycastle.cms.SignerId;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationVerifier;
import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.Mac;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.util.Selector;
import org.spongycastle.util.Store;

/** Funcionalidades criptogr&aacute;ficas de utilidad implementadas mediante proveedores de seguridad JSE
 * (6 y superiores).
 * Contiene c&oacute;digo basado en el trabajo del <i>JMRTD team</i>, bajo licencia
 * GNU Lesser General Public License (LGPL) versi&oacute;n 2.1 o posterior.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author The JMRTD team. */
public final class JseCryptoHelper extends CryptoHelper {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final String ECDH = "ECDH"; //$NON-NLS-1$

	private PaceChannelHelper paceChannelHelper = null;

	// Unicamente anade BouncyCastle si no estaba ya anadido como proveedor
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
		}
	}

    @Override
    public byte[] digest(final DigestAlgorithm algorithm, final byte[] data) throws IOException {

        if (algorithm == null) {
            throw new IllegalArgumentException(
        		"El algoritmo de huella digital no puede ser nulo" //$NON-NLS-1$
    		);
        }
        if (data == null) {
        	throw new IllegalArgumentException(
    			"Los datos para realizar la huella digital no pueden ser nulos" //$NON-NLS-1$
			);
        }

        try {
			return MessageDigest.getInstance(algorithm.toString()).digest(data);
		}
        catch (final NoSuchAlgorithmException e) {
        	throw new IOException(
    			"No se soporta el algoritmo de huella digital indicado ('" + algorithm + "')", e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
    }

    /** Realiza una operaci&oacute;n 3DES.
     * @param data Datos a cifrar o descifrar.
     * @param key Clave 3DES.
     * @param direction Si se debe cifrar o descifrar.
     * @return Datos cifrados o descifrados.
     * @throws IOException Si ocurre cualquier error durante el proceso. */
    private static byte[] doDesede(final byte[] data, final byte[] key, final int direction) throws IOException {
        final byte[] ivBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            ivBytes[i] = 0x00;
        }

        final SecretKey k = new SecretKeySpec(prepareDesedeKey(key), "DESede"); //$NON-NLS-1$
        try {
            final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding"); //$NON-NLS-1$
            cipher.init(direction, k, new IvParameterSpec(ivBytes));
            final byte[] cipheredData = cipher.doFinal(data);
            // Machacamos los datos para evitar que queden en memoria
            for(int i=0;i<data.length;i++) {
                data[i] = '\0';
            }
            return cipheredData;
        }
        catch (final NoSuchAlgorithmException           |
        		     NoSuchPaddingException             |
        		     InvalidKeyException                |
        		     InvalidAlgorithmParameterException |
        		     IllegalBlockSizeException          |
        		     BadPaddingException e) {
            // Machacamos los datos para evitar que queden en memoria
            for(int i=0;i<data.length;i++) {
                data[i] = '\0';
            }
            throw new IOException("Error encriptando datos", e); //$NON-NLS-1$
        }
    }

    @Override
    public byte[] desedeEncrypt(final byte[] data, final byte[] rawKey) throws IOException {
        return doDesede(data, rawKey, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] desedeDecrypt(final byte[] data, final byte[] key) throws IOException {
        return doDesede(data, key, Cipher.DECRYPT_MODE);
    }

    private static byte[] prepareDesedeKey(final byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("La clave 3DES no puede ser nula"); //$NON-NLS-1$
        }
        if (key.length == 24) {
            return key;
        }
        if (key.length == 16) {
            final byte[] newKey = new byte[24];
            System.arraycopy(key, 0, newKey, 0, 16);
            System.arraycopy(key, 0, newKey, 16, 8);
            return newKey;
        }
        throw new IllegalArgumentException(
    		"Longitud de clave invalida, se esperaba 16 o 24, pero se indico " + key.length //$NON-NLS-1$
		);
    }

    private static byte[] doDes(final byte[] data, final byte[] key, final int direction) throws IOException {
        if (key == null) {
            throw new IllegalArgumentException("La clave DES no puede ser nula"); //$NON-NLS-1$
        }
        if (key.length != 8) {
            throw new IllegalArgumentException(
               "La clave DES debe ser de 8 octetos, pero la proporcionada es de " + key.length //$NON-NLS-1$
            );
        }
        try {
            final Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding"); //$NON-NLS-1$
            cipher.init(direction, new SecretKeySpec(key, "DES")); //$NON-NLS-1$
            return cipher.doFinal(data);
        }
        catch (final NoSuchAlgorithmException  |
        		     NoSuchPaddingException    |
        		     InvalidKeyException       |
        		     IllegalBlockSizeException |
        		     BadPaddingException e) {
            throw new IOException("Error cifrando los datos con DES", e); //$NON-NLS-1$
        }
    }

    @Override
    public byte[] desEncrypt(final byte[] data, final byte[] key) throws IOException {
        return doDes(data, key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] desDecrypt(final byte[] data, final byte[] key) throws IOException {
        return doDes(data, key, Cipher.DECRYPT_MODE);
    }

    private static byte[] doRsa(final byte[] cipheredData,
    		                    final RSAKey key,
    		                    final int direction) throws IOException {
        try {
            final Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING"); //$NON-NLS-1$
            dec.init(direction, (Key) key);
            return dec.doFinal(cipheredData);
        }
        catch (final NoSuchAlgorithmException  |
        		     NoSuchPaddingException    |
        		     InvalidKeyException       |
        		     IllegalBlockSizeException |
        		     BadPaddingException e) {
            throw new IOException(
        		"Error cifrando / descifrando los datos mediante la clave RSA", e //$NON-NLS-1$
    		);
        }
    }

    @Override
    public byte[] rsaDecrypt(final byte[] cipheredData, final RSAKey key) throws IOException {
        return doRsa(cipheredData, key, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] rsaEncrypt(final byte[] data, final RSAKey key) throws IOException {
        return doRsa(data, key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] generateRandomBytes(final int numBytes) throws IOException {
        final Random sr;
        try {
            sr = SecureRandom.getInstance("SHA1PRNG"); //$NON-NLS-1$
        }
        catch (final NoSuchAlgorithmException e) {
            throw new IOException("Algoritmo de generacion de aleatorios no valido", e); //$NON-NLS-1$
        }
        final byte[] randomBytes = new byte[numBytes];
        sr.nextBytes(randomBytes);
        return randomBytes;
    }

    private static byte[] aesCrypt(final byte[] data,
    		                       final byte[] iv,
    		                       final byte[] key,
    		                       final String blockmode,
    		                       final String padding,
    		                       final int mode) throws IOException {
		if (data == null) {
			throw new IllegalArgumentException(
				"Los datos a cifrar no pueden ser nulos" //$NON-NLS-1$
			);
		}
		if (key == null) {
			throw new IllegalArgumentException(
				"La clave de cifrado no puede ser nula" //$NON-NLS-1$
			);
		}
		final Cipher aesCipher;
		try {
			aesCipher = Cipher.getInstance(
				"AES/" + blockmode + "/" + (padding != null && !padding.isEmpty() ? padding : "NoPadding") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
		}
		catch (final NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IOException(
				"No se ha podido obtener una instancia del cifrador AES (" + //$NON-NLS-1$
					"AES/" + blockmode + "/" + (padding != null && !padding.isEmpty() ? padding : "NoPadding") + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						")", e //$NON-NLS-1$
			);
		}

		// Vector de inicializacion
		final byte[] ivector;
		if (iv == null) {
			ivector = null;
		}
		else if (iv.length == 0) {
			LOGGER.warning("Se usara un vector de inicializacion AES vacio"); //$NON-NLS-1$
			ivector = new byte[aesCipher.getBlockSize()];
		}
		else {
			ivector = iv;
		}

		try {
			if (iv != null) {
				aesCipher.init(
					mode,
					new SecretKeySpec(key, "AES"), //$NON-NLS-1$
					new IvParameterSpec(ivector)
				);
			}
			else {
				aesCipher.init(
					mode,
					new SecretKeySpec(key, "AES") //$NON-NLS-1$
				);
			}
		}
		catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IOException(
				"La clave proporcionada no es valida", e//$NON-NLS-1$
			);
		}

		try {
			return aesCipher.doFinal(data);
		}
		catch (final IllegalBlockSizeException | BadPaddingException e) {
			throw new IOException(
				"Error en el descifrado, posiblemente los datos proporcionados no sean validos: "  + e, e//$NON-NLS-1$
			);
		}
    }

	@Override
	public byte[] aesDecrypt(final byte[] data,
			                 final byte[] iv,
			                 final byte[] key,
	                         final BlockMode blockMode,
			                 final Padding padding) throws IOException {
		return aesCrypt(data, iv, key, blockMode.toString(), padding.toString(), Cipher.DECRYPT_MODE);
	}

	@Override
	public byte[] aesEncrypt(final byte[] data,
			                 final byte[] iv,
			                 final byte[] key,
	                         final BlockMode blockMode,
			                 final Padding padding) throws IOException {
		return aesCrypt(data, iv, key, blockMode.toString(), padding.toString(), Cipher.ENCRYPT_MODE);
	}

	@Override
	public KeyPair generateEcKeyPair(final EcCurve curveName) throws NoSuchAlgorithmException,
	                                                                 InvalidAlgorithmParameterException {
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
		}
		catch (final NoSuchProviderException e) {
			LOGGER.warning(
				"No se ha podido obtener un generador de pares de claves de curva eliptica con BouncyCastle, se usara el generador por defecto: " + e //$NON-NLS-1$
			);
			kpg = KeyPairGenerator.getInstance(ECDH);
		}

		LOGGER.info(
			"Seleccionado el siguiente generador de claves de curva eliptica: " + kpg.getClass().getName() //$NON-NLS-1$
		);

		final AlgorithmParameterSpec parameterSpec = new ECGenParameterSpec(curveName.toString());
		kpg.initialize(parameterSpec);
		return kpg.generateKeyPair();
	}

	@Override
	public byte[] doAesCmac(final byte[] data, final byte[] key) {
		final BlockCipher cipher = new AESEngine();
		final Mac mac = new CMac(cipher, 64);
		final KeyParameter keyP = new KeyParameter(key);
		mac.init(keyP);
		mac.update(data, 0, data.length);
		final byte[] out = new byte[mac.getMacSize()];
		mac.doFinal(out, 0);
		return out;
	}

	@Override
	public byte[] doEcDh(final Key privateKey,
			             final byte[] publicKey,
			             final EcCurve curveName) throws NoSuchAlgorithmException,
			                                             InvalidKeyException,
			                                             InvalidKeySpecException {
		KeyAgreement ka;
		try {
			ka = KeyAgreement.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
		}
		catch (final NoSuchProviderException e) {
			LOGGER.warning(
				"No se ha podido obtener el KeyAgreement ECDH de BouncyCastle, se intentara el por defecto: " + e //$NON-NLS-1$
			);
			ka = KeyAgreement.getInstance(ECDH);
		}
		ka.init(privateKey);
		ka.doPhase(loadEcPublicKey(publicKey, curveName), true);
		return ka.generateSecret();
	}

	private static Key loadEcPublicKey(final byte [] pubKey,
                                       final EcCurve curveName) throws NoSuchAlgorithmException,
                                                                       InvalidKeySpecException {
	    final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName.toString());
	    KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
		}
		catch (final NoSuchProviderException e) {
			LOGGER.warning(
				"No se ha podido obtener el KeyFactory ECDH de BouncyCastle, se intentara el por defecto: " + e //$NON-NLS-1$
			);
			kf = KeyFactory.getInstance(ECDH);
		}
	    final ECNamedCurveSpec params = new ECNamedCurveSpec(curveName.toString(), spec.getCurve(), spec.getG(), spec.getN());
	    final ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
	    final java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(point, params);
	    return kf.generatePublic(pubKeySpec);
	}

	@Override
	public AlgorithmParameterSpec getEcPoint(final byte[] nonceS, final byte[] sharedSecretH, final EcCurve curveName) {
		final AlgorithmParameterSpec ecParams = ECNamedCurveTable.getParameterSpec(curveName.toString());
		final BigInteger affineX = os2i(sharedSecretH);
		final BigInteger affineY = computeAffineY(affineX, (ECParameterSpec) ecParams);
		final ECPoint sharedSecretPointH = new ECPoint(affineX, affineY);
		return mapNonceGMWithECDH(os2i(nonceS), sharedSecretPointH, (ECParameterSpec) ecParams);
	}

	/** Convierte un <code>Octet String</code> de ASN&#46;1 en un entero
	 * (seg&uacute;n <i>BSI TR 03111</i> Secci&oacute;n 3&#46;1&#46;2).
	 * @param bytes Octet String de ASN&#46;1.
	 * @return Entero (siempre positivo). */
	private static BigInteger os2i(final byte[] bytes) {
		if (bytes == null) {
			throw new IllegalArgumentException();
		}
		return os2i(bytes, 0, bytes.length);
	}

	/** Convierte un <code>Octet String</code> de ASN&#46;1 en un entero
	 * (seg&uacute;n <i>BSI TR 03111</i> Secci&oacute;n 3&#46;1&#46;2).
	 * @param bytes <code>Octet String</code> de ASN&#46;1.
	 * @param offset Desplazamiento (posici&oacute;n de inicio).
	 * @param length Longitud del <code>Octet String</code>.
	 * @return Entero (siempre positivo). */
	private static BigInteger os2i(final byte[] bytes, final int offset, final int length) {
		if (bytes == null) {
			throw new IllegalArgumentException("El Octet String no puede ser nulo"); //$NON-NLS-1$
		}
		BigInteger result = BigInteger.ZERO;
		final BigInteger base = BigInteger.valueOf(256);
		for (int i = offset; i < offset + length; i++) {
			result = result.multiply(base);
			result = result.add(BigInteger.valueOf(bytes[i] & 0xFF));
		}
		return result;
	}

	private static BigInteger computeAffineY(final BigInteger affineX, final ECParameterSpec params) {
		final ECCurve bcCurve = toSpongyCastleECCurve(params);
		final ECFieldElement a = bcCurve.getA();
		final ECFieldElement b = bcCurve.getB();
		final ECFieldElement x = bcCurve.fromBigInteger(affineX);
		final ECFieldElement y = x.multiply(x).add(a).multiply(x).add(b).sqrt();
		return y.toBigInteger();
	}

	private static ECCurve toSpongyCastleECCurve(final ECParameterSpec params) {
		final EllipticCurve curve = params.getCurve();
		final ECField field = curve.getField();
		if (!(field instanceof ECFieldFp)) {
			throw new IllegalArgumentException(
				"Solo se soporta 'ECFieldFp' y se proporciono  " + field.getClass().getCanonicalName() //$NON-NLS-1$
			);
		}
		final int coFactor = params.getCofactor();
		final BigInteger order = params.getOrder();
		final BigInteger a = curve.getA();
		final BigInteger b = curve.getB();
		final BigInteger p = getPrime(params);
		return new ECCurve.Fp(p, a, b, order, BigInteger.valueOf(coFactor));
	}

	private static BigInteger getPrime(final ECParameterSpec params) {
		if (params == null) {
			throw new IllegalArgumentException(
				"Los parametros no pueden ser nulos" //$NON-NLS-1$
			);
		}
		final EllipticCurve curve = params.getCurve();
		final ECField field = curve.getField();
		if (!(field instanceof ECFieldFp)) {
			throw new IllegalStateException(
				"Solo se soporta 'ECFieldFp' y se proporciono  " + field.getClass().getCanonicalName() //$NON-NLS-1$
			);
		}
		return ((ECFieldFp)field).getP();
	}

	private static ECParameterSpec mapNonceGMWithECDH(final BigInteger nonceS,
			                                          final ECPoint sharedSecretPointH,
			                                          final ECParameterSpec params) {
		// D~ = (p, a, b, G~, n, h) where G~ = [s]G + H
		final ECPoint generator = params.getGenerator();
		final EllipticCurve curve = params.getCurve();
		final BigInteger a = curve.getA();
		final BigInteger b = curve.getB();
		final ECFieldFp field = (ECFieldFp)curve.getField();
		final BigInteger p = field.getP();
		final BigInteger order = params.getOrder();
		final int cofactor = params.getCofactor();
		final ECPoint ephemeralGenerator = add(multiply(nonceS, generator, params), sharedSecretPointH, params);
		if (!toSpongyCastleECPoint(ephemeralGenerator, params).isValid()) {
			LOGGER.warning("Se ha generado un punto invalido"); //$NON-NLS-1$
		}
		return new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), ephemeralGenerator, order, cofactor);
	}

	private static ECPoint multiply(final BigInteger s, final ECPoint point, final ECParameterSpec params) {
		final org.spongycastle.math.ec.ECPoint bcPoint = toSpongyCastleECPoint(point, params);
		final org.spongycastle.math.ec.ECPoint bcProd = bcPoint.multiply(s);
		return fromSpongyCastleECPoint(bcProd);
	}

	private static ECPoint fromSpongyCastleECPoint(final org.spongycastle.math.ec.ECPoint point) {
		final org.spongycastle.math.ec.ECPoint newPoint = point.normalize();
		if (!newPoint.isValid()) {
			LOGGER.warning("Se ha proporcionado un punto invalido"); //$NON-NLS-1$
		}
		return new ECPoint(
			newPoint.getAffineXCoord().toBigInteger(),
			newPoint.getAffineYCoord().toBigInteger()
		);
	}

	private static ECPoint add(final ECPoint x, final ECPoint y, final ECParameterSpec params) {
		final org.spongycastle.math.ec.ECPoint bcX = toSpongyCastleECPoint(x, params);
		final org.spongycastle.math.ec.ECPoint bcY = toSpongyCastleECPoint(y, params);
		final org.spongycastle.math.ec.ECPoint bcSum = bcX.add(bcY);
		return fromSpongyCastleECPoint(bcSum);
	}

	private static org.spongycastle.math.ec.ECPoint toSpongyCastleECPoint(final ECPoint point, final ECParameterSpec params) {
		final org.spongycastle.math.ec.ECCurve bcCurve = toSpongyCastleECCurve(params);
		return bcCurve.createPoint(point.getAffineX(), point.getAffineY());
	}

	@Override
	public X509Certificate[] validateCmsSignature(final byte[] signedDataBytes) throws SignatureException, IOException, CertificateException {

		final CMSSignedData cmsSignedData;
		try {
			cmsSignedData = new CMSSignedData(signedDataBytes);
		}
		catch (final CMSException e2) {
			throw new IOException("Los datos no son un SignedData de PKCS#7/CMS", e2); //$NON-NLS-1$
		}
		final Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
		final List<X509Certificate> certChain = new ArrayList<>();
		for (final SignerInformation si : cmsSignedData.getSignerInfos().getSigners()) {
			final Iterator<X509CertificateHolder> certIt = store.getMatches(
				new CertHolderBySignerIdSelector(si.getSID())
			).iterator();
			final X509Certificate cert;
            try {
				cert = CertificateUtils.generateCertificate(certIt.next().getEncoded());
			}
            catch (final IOException e1) {
            	throw new CertificateException(
					"El SignedData contiene un certificado en formato incorrecto", e1//$NON-NLS-1$
				);
			}
            try {
				cert.checkValidity();
			}
            catch (final CertificateExpiredException | CertificateNotYetValidException e1) {
            	throw new CertificateException(
					"El SignedData contiene un certificado fuera de su periodo temporal de validez", e1 //$NON-NLS-1$
				);
			}
			try {
				if (
					!si.verify(
						new SignerInformationVerifier(
							new	DefaultCMSSignatureAlgorithmNameGenerator(),
							new DefaultSignatureAlgorithmIdentifierFinder(),
							new JcaContentVerifierProviderBuilder().setProvider(
								new BouncyCastleProvider()
							).build(cert),
							new BcDigestCalculatorProvider()
						)
					)
				) {
					throw new SignatureException("Firma del SOD no valida"); //$NON-NLS-1$
				}
			}
			catch (final OperatorCreationException | CMSException e) {
				throw new SignatureException(
					"No se ha podido comprobar la firma del SOD", e //$NON-NLS-1$
				);
			}
            certChain.add(cert);
		}
		return certChain.toArray(new X509Certificate[certChain.size()]);
	}

	/** Selector interno para la lectura de los certificados del firmante del SOD. */
	private static final class CertHolderBySignerIdSelector implements Selector<X509CertificateHolder> {

		private final SignerId signerId;

		CertHolderBySignerIdSelector(final SignerId sid) {
			if (sid == null) {
				throw new IllegalArgumentException("El ID del firmante no puede ser nulo"); //$NON-NLS-1$
			}
			this.signerId = sid;
		}

		@Override
		public boolean match(final X509CertificateHolder o) {
			return CertHolderBySignerIdSelector.this.signerId.getSerialNumber().equals(
				o.getSerialNumber()
			);
		}

		@Override
		public Object clone() {
			throw new UnsupportedOperationException();
		}
	}

	@Override
	public byte[] getCmsSignatureSignedContent(final byte[] signedDataBytes) throws IOException {
		final CMSSignedData cmsSignedData;
		try {
			cmsSignedData = new CMSSignedData(signedDataBytes);
		}
		catch (final CMSException e2) {
			throw new IOException("Los datos no son un SignedData de PKCS#7/CMS", e2); //$NON-NLS-1$
		}
		return (byte[]) cmsSignedData.getSignedContent().getContent();
	}

	@Override
	public PaceChannelHelper getPaceChannelHelper() {
		// Solo creamos el PaceChannelHelper si nos lo piden,
		// asi evitamos crearlo en uso con contactos (PACE solo
		// se usa con NFC).
		if (this.paceChannelHelper == null) {
			this.paceChannelHelper = new PaceChannelHelperBc(this);
		}
		return this.paceChannelHelper;
	}

}