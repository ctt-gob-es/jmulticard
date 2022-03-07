package es.gob.jmulticard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
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
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
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
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.Mac;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.prng.DigestRandomGenerator;
import org.spongycastle.crypto.prng.RandomGenerator;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.util.Selector;
import org.spongycastle.util.Store;

/** Funcionalidades criptogr&aacute;ficas de utilidad implementadas mediante BouncyCastle.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class BcCryptoHelper extends CryptoHelper {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final String ECDH = "ECDH"; //$NON-NLS-1$

	private PaceChannelHelper paceChannelHelper = null;

	// Unicamente anade BouncyCastle si no estaba ya anadido como proveedor
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
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
    	byte[] out;
    	switch(algorithm) {
	    	case SHA512:
	    		final SHA512Digest digest512 = new SHA512Digest();
	    		digest512.update(data, 0, data.length);
	    		out = new byte[digest512.getDigestSize()];
	    		digest512.doFinal(out, 0);
	    		break;
	    	case SHA384:
	    		final SHA384Digest digest384 = new SHA384Digest();
	    		digest384.update(data, 0, data.length);
	    		out = new byte[digest384.getDigestSize()];
	    		digest384.doFinal(out, 0);
	    		break;
	    	case SHA256:
	    		final SHA256Digest digest256 = new SHA256Digest();
	    		digest256.update(data, 0, data.length);
	    		out = new byte[digest256.getDigestSize()];
	    		digest256.doFinal(out, 0);
	    		break;
	    	case SHA1:
	    		final SHA1Digest digest = new SHA1Digest();
	    		digest.update(data, 0, data.length);
	    		out = new byte[digest.getDigestSize()];
	    		digest.doFinal(out, 0);
	    		break;
	    	default:
	        	throw new IOException(
        			"No se soporta el algoritmo de huella digital indicado: " + algorithm //$NON-NLS-1$
    			);
    	}
    	return out;
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
        catch (final Exception e) {
            // Machacamos los datos para evitar que queden en memoria
            for(int i=0;i<data.length;i++) {
                data[i] = '\0';
            }
            throw new IOException("Error encriptando datos: " + e, e); //$NON-NLS-1$
        }
    }

    @Override
    public byte[] desedeEncrypt(final byte[] data, final byte[] key) throws IOException {
        return doDesede(data, key, Cipher.ENCRYPT_MODE);
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
        catch (final Exception e) {
            throw new IOException("Error cifrando los datos con DES: " + e, e); //$NON-NLS-1$
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
    		                    final Key key,
    		                    final int direction) throws IOException {
        try {
            final Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING"); //$NON-NLS-1$
            dec.init(direction, key);
            return dec.doFinal(cipheredData);
        }
        catch (final Exception e) {
            throw new IOException(
        		"Error cifrando / descifrando los datos mediante la clave RSA: " + e, e //$NON-NLS-1$
    		);
        }
    }

    @Override
    public byte[] rsaDecrypt(final byte[] cipheredData, final Key key) throws IOException {
        return doRsa(cipheredData, key, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] rsaEncrypt(final byte[] data, final Key key) throws IOException {
        return doRsa(data, key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] generateRandomBytes(final int numBytes) {
    	final RandomGenerator sr = new DigestRandomGenerator(new SHA1Digest());
    	final byte[] ret = new byte[numBytes];
    	sr.nextBytes(ret);
    	return ret;
    }

	/** Encripta un bloque usando AES.
	 * @param key Clave AES.
	 * @param z Bloque a crifrar.
	 * @return Bloque cifrado. */
	private static byte[] encryptBlock(final byte[] key, final byte[] z) {
		final KeyParameter encKey = new KeyParameter(key);
		final BlockCipher cipher = new AESEngine();
		cipher.init(true, encKey);
		final byte[] s = new byte[cipher.getBlockSize()];
		cipher.processBlock(z, 0, s, 0);
		return s;
	}

    private static byte[] bcAesEncrypt(final byte[] data,
                                       final byte[] iv,
                                       final byte[] aesKey,
                                       final BlockCipherPadding padding) throws DataLengthException,
                                                                                IllegalStateException,
                                                                                InvalidCipherTextException,
                                                                                IOException {
    	final BlockCipher engine = new AESEngine();

		// Vector de inicializacion
		final byte[] ivector;
		if (iv == null) {
			ivector = null;
		}
		else if (iv.length == 0) {
			LOGGER.warning("Se usara un vector de inicializacion AES vacio"); //$NON-NLS-1$
			ivector = new byte[engine.getBlockSize()];
		}
		else {
			ivector = iv;
		}

		int noBytesRead = 0; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		// AES block cipher en modo CBC
		final BufferedBlockCipher encryptCipher =
			padding != null ?
				// Con relleno
				new PaddedBufferedBlockCipher(
					new CBCBlockCipher(
						new AESEngine()
					),
					padding) :
						// Sin relleno
						new BufferedBlockCipher(
							new CBCBlockCipher(
								engine
							)
						);

		// Creamos los parametros de cifrado con el vector de inicializacion (iv)
		final ParametersWithIV parameterIV = new ParametersWithIV(
			new KeyParameter(aesKey),
			ivector
		);
		// Inicializamos
		encryptCipher.init(true, parameterIV);

		// Buffers para mover octetos de un flujo a otro
		final byte[] buf = new byte[16]; // Buffer de entrada
		final byte[] obuf = new byte[512]; // Buffer de salida

		try (
			final InputStream bin = new ByteArrayInputStream(data);
			final ByteArrayOutputStream bout = new ByteArrayOutputStream()
		) {
			while ((noBytesRead = bin.read(buf)) >= 0) {
				noBytesProcessed = encryptCipher.processBytes(
					buf,
					0,
					noBytesRead,
					obuf,
					0
				);
				bout.write(obuf, 0, noBytesProcessed);
			}

			noBytesProcessed = encryptCipher.doFinal(obuf, 0);
			bout.write(obuf, 0, noBytesProcessed);
			bout.flush();
			return bout.toByteArray();
		}
    }

    private static byte[] bcAesDecrypt(final byte[] data,
    		                           final byte[] iv,
    		                           final byte[] key,
    		                           final BlockCipherPadding padding) throws IOException,
                                                                                DataLengthException,
                                                                                IllegalStateException,
                                                                                InvalidCipherTextException {
		final BlockCipher engine = new AESEngine();

		// Vector de inicializacion
		final byte[] ivector;
		if (iv == null) {
			ivector = null;
		}
		else if (iv.length == 0) {
			LOGGER.warning("Se usara un vector de inicializacion AES vacio"); //$NON-NLS-1$
			ivector = new byte[engine.getBlockSize()];
		}
		else {
			ivector = iv;
		}

		// Creamos los parametros de descifrado con el vector de inicializacion (iv)
		final ParametersWithIV parameterIV = new ParametersWithIV(
			new KeyParameter(key),
			ivector
		);

		int noBytesRead = 0; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		// AES block cipher en modo CBC
		final BufferedBlockCipher decryptCipher =
			padding != null ?
				// Con relleno
				new PaddedBufferedBlockCipher(
					new CBCBlockCipher(
						new AESEngine()
					),
					padding) :
						// Sin relleno
						new BufferedBlockCipher(
							new CBCBlockCipher(
								engine
							)
						);

		// Inicializamos
		decryptCipher.init(false, parameterIV);

		// Buffers para mover octetos de un flujo a otro
		final byte[] buf = new byte[16]; // Buffer de entrada
		final byte[] obuf = new byte[512]; // Buffer de salida

		try (
			final InputStream bin = new ByteArrayInputStream(data);
			final ByteArrayOutputStream bout = new ByteArrayOutputStream()
		) {
			while ((noBytesRead = bin.read(buf)) >= 0) {
				noBytesProcessed = decryptCipher.processBytes(
					buf,
					0,
					noBytesRead,
					obuf,
					0
				);
				bout.write(obuf, 0, noBytesProcessed);
			}

			noBytesProcessed = decryptCipher.doFinal(obuf, 0);
			bout.write(obuf, 0, noBytesProcessed);
			bout.flush();

			return bout.toByteArray();
		}
    }

	@Override
	public byte[] aesDecrypt(final byte[] data,
			                 final byte[] iv,
			                 final byte[] key,
	                         final BlockMode blockMode,
			                 final Padding padding) throws IOException {
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
		final BlockCipherPadding bcPadding;
		switch(padding) {
			case NOPADDING:
				bcPadding = null;
				break;
			case ISO7816_4PADDING:
				bcPadding = new ISO7816d4Padding();
				break;
			default:
				throw new IOException(
					"Algoritmo de relleno no soportado para AES: " + padding //$NON-NLS-1$
				);
		}
		try {
			return bcAesDecrypt(data, iv, key, bcPadding);
		}
		catch (final DataLengthException   |
				     IllegalStateException |
				     InvalidCipherTextException e) {
			throw new IOException(
				"Error en el descifrado AES: "+ e, e //$NON-NLS-1$
			);
		}
	}

	@Override
	public byte[] aesEncrypt(final byte[] data,
			                 final byte[] iv,
			                 final byte[] key,
	                         final BlockMode blockMode,
			                 final Padding padding) throws IOException {
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

		// Si es un cifrado ECB sin relleno y los datos son exactamente un bloque,
		// hacemos la operacion directamente
		if (BlockMode.ECB.equals(blockMode) && Padding.NOPADDING.equals(padding) && data.length == 16) {
			return encryptBlock(key, data);
		}

		final BlockCipherPadding bcPadding;
		switch(padding) {
			case NOPADDING:
				bcPadding = null;
				break;
			case ISO7816_4PADDING:
				bcPadding = new ISO7816d4Padding();
				break;
			default:
				throw new IOException(
					"Algoritmo de relleno no soportado para AES: " + padding //$NON-NLS-1$
				);
		}
		try {
			return bcAesEncrypt(
				data,
				iv,
				key,
				bcPadding
			);
		}
		catch (final DataLengthException        |
				     IllegalStateException      |
				     InvalidCipherTextException |
				     IOException e) {
			throw new IOException(
				"Error en el cifrado AES: " + e, e //$NON-NLS-1$
			);
		}
	}

	@Override
	public KeyPair generateEcKeyPair(final EcCurve curveName) throws NoSuchAlgorithmException,
	                                                                 InvalidAlgorithmParameterException {

		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
		}
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
		}
		catch (final Exception e) {
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

		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
		}

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
			throw new IOException("Los datos no son un SignedData de PKCS#7/CMS: " + e2, e2); //$NON-NLS-1$
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
					"El SignedData contiene un certificado en formato incorrecto: " + e1, e1//$NON-NLS-1$
				);
			}
            try {
				cert.checkValidity();
			}
            catch (final CertificateExpiredException | CertificateNotYetValidException e1) {
            	throw new CertificateException(
					"El SignedData contiene un certificado fuera de su periodo temporal de validez: " + e1, e1 //$NON-NLS-1$
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
			catch (final Exception e) {
				throw new SignatureException(
					"No se ha podido comprobar la firma del SOD: " + e, e //$NON-NLS-1$
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
			throw new IOException("Los datos no son un SignedData de PKCS#7/CMS: " + e2, e2); //$NON-NLS-1$
		}
		return (byte[]) cmsSignedData.getSignedContent().getContent();
	}

	@Override
	public PaceChannelHelper getPaceChannelHelper() {
		// Solo creamos el PaceChannelHelper si nos lo piden, asi
		// evitamos crearlo en uso con contactos (PACE solo se usa con NFC).
		if (this.paceChannelHelper == null) {
			this.paceChannelHelper = new PaceChannelHelperBc(this);
		}
		return this.paceChannelHelper;
	}

}