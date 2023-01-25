package es.gob.jmulticard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.spongycastle.cms.SignerId;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationVerifier;
import org.spongycastle.crypto.AsymmetricBlockCipher;
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
import org.spongycastle.crypto.engines.DESEngine;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.prng.DigestRandomGenerator;
import org.spongycastle.crypto.prng.RandomGenerator;
import org.spongycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.spongycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.util.Selector;
import org.spongycastle.util.Store;

/** Funcionalidades criptogr&aacute;ficas de utilidad implementadas mediante BouncyCastle.
 * Contiene c&oacute;digo basado en el trabajo del <i>JMRTD team</i>, bajo licencia
 * GNU Lesser General Public License (LGPL) versi&oacute;n 2.1 o posterior.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author The JMRTD team. */
public final class BcCryptoHelper extends CryptoHelper {

	/** Logger por defecto. */
	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private transient PaceChannelHelper paceChannelHelper = null;

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
     * @param forEncryption Si se debe cifrar o descifrar.
     * @return Datos cifrados o descifrados.
     * @throws IOException Si ocurre cualquier error durante el proceso. */
    private static byte[] doDesede(final byte[] data,
    		                       final byte[] key,
    		                       final boolean forEncryption) throws IOException {
		final BufferedBlockCipher cipher = new BufferedBlockCipher(
			new CBCBlockCipher(new DESedeEngine())
		);
		cipher.init(
			forEncryption,
			new KeyParameter(
				prepareDesedeKey(key)
			)
		);
		final byte[] result = new byte[cipher.getOutputSize(data.length)];
		final int tam = cipher.processBytes(data, 0, data.length, result, 0);
		try {
			cipher.doFinal(result, tam);
		}
		catch (final DataLengthException   |
				     IllegalStateException |
				     InvalidCipherTextException e) {
			throw new IOException("Error en el cifrado o descifrado 3DES", e); //$NON-NLS-1$
		}
		return result;
    }

    @Override
    public byte[] desedeEncrypt(final byte[] data, final byte[] rawKey) throws IOException {
        return doDesede(data, rawKey, true);
    }

    @Override
    public byte[] desedeDecrypt(final byte[] data, final byte[] rawKey) throws IOException {
        return doDesede(data, rawKey, false);
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

    private static byte[] doDes(final byte[] data,
    		                    final byte[] key,
    		                    final boolean forEncryption) throws IOException {
    	final BlockCipher engine = new DESEngine();
    	final BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
    	cipher.init(forEncryption, new KeyParameter(key));
    	final byte[] cipherText = new byte[cipher.getOutputSize(data.length)];
    	final int outputLen = cipher.processBytes(data, 0, data.length, cipherText, 0);
    	try {
			cipher.doFinal(cipherText, outputLen);
		}
    	catch (final DataLengthException   |
    			     IllegalStateException |
    			     InvalidCipherTextException e) {
			throw new IOException("Error el el cifrado / descifrado DES", e); //$NON-NLS-1$
		}
    	return cipherText;
    }

    @Override
    public byte[] desEncrypt(final byte[] data, final byte[] key) throws IOException {
    	return doDes(data, key, true);
    }

    @Override
    public byte[] desDecrypt(final byte[] data, final byte[] key) throws IOException {
    	return doDes(data, key, false);
    }

    private static byte[] doRsa(final byte[] data,
    		                    final RSAKey key,
    		                    final boolean forEncryption) throws IOException {

    	final boolean isPrivateKey = key instanceof RSAPrivateKey;

    	final AsymmetricKeyParameter akp = new RSAKeyParameters(
			isPrivateKey,
			key.getModulus(),
			isPrivateKey ?
				((RSAPrivateKey)key).getPrivateExponent() :
					((RSAPublicKey)key).getPublicExponent()
		);
    	final AsymmetricBlockCipher cipher = new RSAEngine();
    	cipher.init(forEncryption, akp);

    	try {
			return cipher.processBlock(data, 0, data.length);
		}
    	catch (final InvalidCipherTextException e) {
			throw new IOException("Error en el cifrado/descifrado RSA", e); //$NON-NLS-1$
		}
    }

    @Override
    public byte[] rsaDecrypt(final byte[] cipheredData, final RSAKey key) throws IOException {
        return doRsa(cipheredData, key, false);
    }

    @Override
    public byte[] rsaEncrypt(final byte[] data, final RSAKey key) throws IOException {
        return doRsa(data, key, true);
    }

    @Override
    public byte[] generateRandomBytes(final int numBytes) {
    	final RandomGenerator sr = new DigestRandomGenerator(new SHA1Digest());
    	final byte[] ret = new byte[numBytes];
    	sr.nextBytes(ret);
    	return ret;
    }

	/** Encripta un &uacute;nico bloque usando AES.
	 * @param key Clave AES.
	 * @param dataBlock Bloque a crifrar.
	 * @return Bloque cifrado. */
	private static byte[] aesEncryptSingleBlock(final byte[] key, final byte[] dataBlock) {
		final KeyParameter encKey = new KeyParameter(key);
		final BlockCipher cipher = new AESEngine();
		cipher.init(true, encKey);
		final byte[] s = new byte[cipher.getBlockSize()];
		cipher.processBlock(dataBlock, 0, s, 0);
		return s;
	}

    private static byte[] doAes(final byte[] data,
    		                    final byte[] iv,
    		                    final byte[] aesKey,
    		                    final BlockCipherPadding padding,
    		                    final boolean forEncryption) throws IOException,
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

		// Creamos los parametros de cifrado con el vector de inicializacion (iv)
		final ParametersWithIV parameterIV = new ParametersWithIV(
			new KeyParameter(aesKey),
			ivector
		);

		int noBytesRead; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		// AES block cipher en modo CBC
		final BufferedBlockCipher aesCipher =
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
		aesCipher.init(forEncryption, parameterIV);

		// Buffers para mover octetos de un flujo a otro
		final byte[] buf = new byte[16]; // Buffer de entrada
		final byte[] obuf = new byte[512]; // Buffer de salida

		try (
			final InputStream bin = new ByteArrayInputStream(data);
			final ByteArrayOutputStream bout = new ByteArrayOutputStream()
		) {
			while ((noBytesRead = bin.read(buf)) >= 0) {
				noBytesProcessed = aesCipher.processBytes(
					buf,
					0,
					noBytesRead,
					obuf,
					0
				);
				bout.write(obuf, 0, noBytesProcessed);
			}

			noBytesProcessed = aesCipher.doFinal(obuf, 0);
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
			return doAes(data, iv, key, bcPadding, false);
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
			return aesEncryptSingleBlock(key, data);
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
			return doAes(
				data,
				iv,
				key,
				bcPadding,
				true
			);
		}
		catch (final DataLengthException        |
				     IllegalStateException      |
				     InvalidCipherTextException |
				     IOException e) {
			throw new IOException(
				"Error en el cifrado AES", e //$NON-NLS-1$
			);
		}
	}

	@Override
	public KeyPair generateEcKeyPair(final EcCurve curveName) throws NoSuchAlgorithmException,
	                                                                 InvalidAlgorithmParameterException {
		final KeyPairGenerator kpg = new KeyPairGeneratorSpi.ECDH();
		final AlgorithmParameterSpec parameterSpec = new ECNamedCurveGenParameterSpec(
			curveName.toString()
		);
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
	public AlgorithmParameterSpec getEcPoint(final byte[] nonceS,
			                                 final byte[] sharedSecretH,
			                                 final EcCurve curveName) {
		final AlgorithmParameterSpec ecParams = ECNamedCurveTable.getParameterSpec(
			curveName.toString()
		);
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
		final ECPoint ephemeralGenerator = add(
			multiply(nonceS, generator, params),
			sharedSecretPointH,
			params
		);
		if (!toSpongyCastleECPoint(ephemeralGenerator, params).isValid()) {
			LOGGER.warning("Se ha generado un punto invalido"); //$NON-NLS-1$
		}
		return new ECParameterSpec(
			new EllipticCurve(new ECFieldFp(p), a, b),
			ephemeralGenerator,
			order,
			cofactor
		);
	}

	private static ECPoint multiply(final BigInteger s,
			                        final ECPoint point,
			                        final ECParameterSpec params) {
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

	private static org.spongycastle.math.ec.ECPoint toSpongyCastleECPoint(final ECPoint point,
			                                                              final ECParameterSpec params) {
		final org.spongycastle.math.ec.ECCurve bcCurve = toSpongyCastleECCurve(params);
		return bcCurve.createPoint(point.getAffineX(), point.getAffineY());
	}

	@Override
	public X509Certificate[] validateCmsSignature(final byte[] signedDataBytes) throws SignatureException,
	                                                                                   IOException,
	                                                                                   CertificateException {
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
				cert = generateCertificate(certIt.next().getEncoded());
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

		private transient final SignerId signerId;

		CertHolderBySignerIdSelector(final SignerId sid) {
			if (sid == null) {
				throw new IllegalArgumentException("El ID del firmante no puede ser nulo"); //$NON-NLS-1$
			}
			signerId = sid;
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

	/** Genera un certificado a partir de su codificaci&oacute;n binaria.
	 * @param encoded Codificaci&oacute;n binaria del certificado.
	 * @return Certificado.
	 * @throws CertificateException Si la codificaci&oacute;n binaria no correspond&iacute;a a un
	 *                              certificado. */
	@Override
	public X509Certificate generateCertificate(final byte[] encoded) throws CertificateException {
		return generateCertificate(new ByteArrayInputStream(encoded));
	}

	/** Genera un certificado a partir de un flujo hacia su codificaci&oacute;n binaria.
	 * @param is Flujo de lectura hacia la Codificaci&oacute;n binaria del certificado.
	 * @return Certificado.
	 * @throws CertificateException Si la codificaci&oacute;n binaria no correspond&iacute;a a un
	 *                              certificado o no se pudo leer del flujo de entrada. */
	@Override
	public X509Certificate generateCertificate(final InputStream is) throws CertificateException {
		return (X509Certificate) new CertificateFactory().engineGenerateCertificate(is);
	}

	@Override
	public PaceChannelHelper getPaceChannelHelper() {
		// Solo creamos el PaceChannelHelper si nos lo piden, asi
		// evitamos crearlo en uso con contactos (PACE solo se usa con NFC).
		if (paceChannelHelper == null) {
			paceChannelHelper = new BcPaceChannelHelper(this);
		}
		return paceChannelHelper;
	}

}