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

package test.es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.ByteArrayInputStream;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;

import es.gob.jmulticard.CryptoHelper;

/** Funcionalidades criptogr&aacute;ficas de utilidad implementadas mediante proveedores de seguridad JSE6.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class JseCryptoHelper extends CryptoHelper {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final String ECDH = "ECDH"; //$NON-NLS-1$

    /** {@inheritDoc} */
    @Override
    public byte[] digest(final DigestAlgorithm algorithm, final byte[] data) throws IOException {

        if (algorithm == null) {
            throw new IllegalArgumentException("El algoritmo de huella digital no puede ser nulo"); //$NON-NLS-1$
        }
        if (data == null) {
        	throw new IllegalArgumentException("Los datos para realizar la huella digital no pueden ser nulos"); //$NON-NLS-1$
        }

        try {
			return MessageDigest.getInstance(algorithm.toString()).digest(data);
		}
        catch (final NoSuchAlgorithmException e) {
        	throw new IOException(
    			"El sistema no soporta el algoritmo de huella digital indicado ('" + algorithm + "'): " + e, e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
    }

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
        catch (final Exception e) {
            // Machacamos los datos para evitar que queden en memoria
            for(int i=0;i<data.length;i++) {
                data[i] = '\0';
            }
            throw new IOException("Error encriptando datos: " + e, e); //$NON-NLS-1$
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] desedeEncrypt(final byte[] data, final byte[] key) throws IOException {
        return doDesede(data, key, Cipher.ENCRYPT_MODE);
    }

    /** {@inheritDoc} */
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
        throw new IllegalArgumentException("Longitud de clave invalida, se esperaba 16 o 24, pero se indico " + Integer.toString(key.length)); //$NON-NLS-1$
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
        catch (final Exception e) {
            throw new IOException("Error cifrando los datos con DES: " + e, e); //$NON-NLS-1$
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] desEncrypt(final byte[] data, final byte[] key) throws IOException {
        return doDes(data, key, Cipher.ENCRYPT_MODE);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] desDecrypt(final byte[] data, final byte[] key) throws IOException {
        return doDes(data, key, Cipher.DECRYPT_MODE);
    }

    private static byte[] doRsa(final byte[] cipheredData, final Key key, final int direction) throws IOException {
        try {
            final Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING"); //$NON-NLS-1$
            dec.init(direction, key);
            return dec.doFinal(cipheredData);
        }
        catch (final Exception e) {
            throw new IOException("Error cifrando/descifrando los datos mediante la clave RSA: " + e, e); //$NON-NLS-1$
        }

    }

    /** {@inheritDoc} */
    @Override
    public byte[] rsaDecrypt(final byte[] cipheredData, final Key key) throws IOException {
        return doRsa(cipheredData, key, Cipher.DECRYPT_MODE);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] rsaEncrypt(final byte[] data, final Key key) throws IOException {
        return doRsa(data, key, Cipher.ENCRYPT_MODE);
    }

    /** {@inheritDoc} */
    @Override
    public Certificate generateCertificate(final byte[] encode) throws CertificateException {
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encode)); //$NON-NLS-1$
    }

    /** {@inheritDoc} */
    @Override
    public byte[] generateRandomBytes(final int numBytes) throws IOException {
        final SecureRandom sr;
        try {
            sr = SecureRandom.getInstance("SHA1PRNG"); //$NON-NLS-1$
        }
        catch (final NoSuchAlgorithmException e) {
            throw new IOException("Algoritmo de generacion de aleatorios no valido: " + e, e); //$NON-NLS-1$
        }
        final byte[] randomBytes = new byte[numBytes];
        sr.nextBytes(randomBytes);
        return randomBytes;
    }

    private static byte[] aesCrypt(final byte[] data, final byte[] iv, final byte[] key, final int mode) throws IOException {
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
			aesCipher = Cipher.getInstance("AES/CBC/NoPadding"); //$NON-NLS-1$
		}
		catch (final Exception e) {
			throw new IOException(
				"No se ha podido obtener una instancia del cifrador 'AES/CBC/NoPadding': " + e, e //$NON-NLS-1$
			);
		}

		// Vector de inicializacion
		final byte[] ivector;
		if (iv == null) {
			// Creamos el IV de forma aleatoria, porque ciertos proveedores (como Android) dan arrays fijos
			// para IvParameterSpec.getIV(), normalmente todo ceros
			LOGGER.info("Se usara un vector de inicializacion AES aleatorio"); //$NON-NLS-1$
			ivector = new byte[aesCipher.getBlockSize()];
			new SecureRandom().nextBytes(ivector);
		}
		else if (iv.length == 0) {
			LOGGER.warning("Se usara un vector de inicializacion AES vacio"); //$NON-NLS-1$
			ivector = new byte[aesCipher.getBlockSize()];
		}
		else {
			ivector = iv;
		}

		try {
			aesCipher.init(
				mode,
				new SecretKeySpec(key, "AES"), //$NON-NLS-1$
				new IvParameterSpec(ivector)
			);
		}
		catch (final Exception e) {
			throw new IOException(
				"La clave proporcionada no es valida: " + e, e//$NON-NLS-1$
			);
		}

		try {
			return aesCipher.doFinal(data);
		}
		catch (final Exception e) {
			e.printStackTrace();
			throw new IOException(
				"Error en el descifrado, posiblemente los datos proporcionados no sean validos: "  + e, e//$NON-NLS-1$
			);
		}
    }

	@Override
	public byte[] aesDecrypt(final byte[] data, final byte[] iv, final byte[] key) throws IOException {
		return aesCrypt(data, iv, key, Cipher.DECRYPT_MODE);
	}

	@Override
	public byte[] aesEncrypt(final byte[] data, final byte[] iv, final byte[] key) throws IOException {
		return aesCrypt(data, iv, key, Cipher.ENCRYPT_MODE);
	}

	@Override
	public KeyPair generateEcKeyPair(final EcCurve curveName) throws NoSuchAlgorithmException,
	                                                                 InvalidAlgorithmParameterException {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
		}
		catch (final Exception e) {
			Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
				"No se ha podido obtener un generador de pares de claves de curva eliptica con SpongyCastle, se usara el generador por defecto: " + e //$NON-NLS-1$
			);
			kpg = KeyPairGenerator.getInstance("EC"); //$NON-NLS-1$
		}

		Logger.getLogger("es.gob.jmulticard").info( //$NON-NLS-1$
			"Seleccionado el siguiente generador de claves de curva eliptica: " + kpg.getClass().getName() //$NON-NLS-1$
		);

		final AlgorithmParameterSpec parameterSpec = new ECGenParameterSpec(curveName.toString());
		kpg.initialize(parameterSpec);
		return kpg.generateKeyPair();
	}

	@Override
	public byte[] doAesCmac(final byte[] data, final byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		final Mac eng = Mac.getInstance("AESCMAC", new BouncyCastleProvider()); //$NON-NLS-1$
		eng.init(new SecretKeySpec(key, "AES")); //$NON-NLS-1$
		return eng.doFinal(data);
	}

	@Override
	public byte[] doEcDh(final Key privateKey,
			             final byte[] publicKey,
			             final EcCurve curveName) throws NoSuchAlgorithmException,
			                                             InvalidKeyException,
			                                             InvalidKeySpecException {

		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		KeyAgreement ka;
		try {
			ka = KeyAgreement.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
		}
		catch (final NoSuchProviderException e) {
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

	/** Convierte un Octet String de ASN&#46;1 en un entero
	 * (seg&uacute;n <i>BSI TR 03111</i> Secci&oacute;n 3N&#46;1N&#46;2).
	 * @param bytes <code>Octet String</code> de ASN&#46;1.
	 * @return Entero (siempre positivo). */
	private static BigInteger os2i(final byte[] bytes) {
		if (bytes == null) { throw new IllegalArgumentException(); }
		return os2i(bytes, 0, bytes.length);
	}

	/** Convierte un Octet String de ASN&#46;1 en un entero
	 * (seg&uacute;n <i>BSI TR 03111</i> Secci&oacute;n 3N&#46;1N&#46;2).
	 * @param bytes <code>Octet String</code> de ASN&#46;1.
	 * @param offset Posici&oacute;n de inicio-
	 * @param length Longitud del Octet String.
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
			LOGGER.warning("Se ha proporcionaod un punto invalido"); //$NON-NLS-1$
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

}