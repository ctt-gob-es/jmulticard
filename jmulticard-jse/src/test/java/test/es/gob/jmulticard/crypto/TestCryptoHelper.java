package test.es.gob.jmulticard.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.engines.DESedeEngine;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveGenParameterSpec;

import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.EcCurve;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.HexUtils;


/** Pruebas de operaciones criptogr&aacute;ficas con BcCryptoHelper.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestCryptoHelper {

	private static final CryptoHelper CH = new BcCryptoHelper();

	/** Pruebas de descifrado AES.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testAesDecrypt() throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		final String testString = "prhjdhakjshdkahskjdhaksdhkjashdkjahsjkdhkajshkdueb"; //$NON-NLS-1$
		final byte[] key = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
		};
		final byte[] iv = {
			0x04, 0x00, 0x06, 0x00, 0x00, (byte) 0xee, 0x00, 0x30,
			0x00, 0x01, 0x00, 0x08, (byte) 0xff, 0x00, 0x20, 0x00
		};
		final byte[] in = new BcCryptoHelper().aesEncrypt(
			testString.getBytes(),
			iv,
			key,
			BlockMode.CBC,
			Padding.ISO7816_4PADDING
		);


		// BouncyCastle puro

		// Creamos los parametros de descifrado con el vector de inicializacion (iv)
		final ParametersWithIV parameterIV = new ParametersWithIV(
			new KeyParameter(key),
			iv
		);

		int noBytesRead; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		final BufferedBlockCipher decryptCipher = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
				new AESEngine()
			),
			new ISO7816d4Padding()
		);

		// Inicializamos
		decryptCipher.init(false, parameterIV);

		// Buffers para mover octetos de un flujo a otro
		final byte[] buf = new byte[16]; // Buffer de entrada
		final byte[] obuf = new byte[512]; // Buffer de salida

		try (
			final InputStream bin = new ByteArrayInputStream(in);
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

			System.out.println(HexUtils.hexify(bout.toByteArray(), false));
		}


		// Ahora con JCA/JCE

		final Cipher aesCipher = Cipher.getInstance(
			"AES/CBC/ISO7816-4Padding" //$NON-NLS-1$
		);
		aesCipher.init(
			Cipher.DECRYPT_MODE,
			new SecretKeySpec(key, "AES"), //$NON-NLS-1$
			new IvParameterSpec(iv)
		);

		System.out.println(HexUtils.hexify(aesCipher.doFinal(in), false));

	}

	/** Pruebas de cifrado AES.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testAesEncrypt() throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		// BouncyCastle usando JCE/JCA puro
		final String testString = "prhjdhakjshdkahskjdhaksdhkjashdkjahsjkdhkajshkdueb"; //$NON-NLS-1$
		final byte[] testBytes = testString.getBytes();
		final byte[] aesKey = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
		};
		final byte[] iv = {
			0x04, 0x00, 0x06, 0x00, 0x00, (byte) 0xee, 0x00, 0x30,
			0x00, 0x01, 0x00, 0x08, (byte) 0xff, 0x00, 0x20, 0x00
		};

		byte[] tmp = CH.aesEncrypt(
			testBytes,
			iv,
			aesKey,
			BlockMode.CBC,
			Padding.ISO7816_4PADDING
		);
		System.out.println(HexUtils.hexify(tmp, false));

		//**********************************************************
		//**********************************************************

		// BouncyCastle directo
		int noBytesRead; // Numero de octetos leidos de la entrada
		int noBytesProcessed = 0; // Numero de octetos procesados

		// AES block cipher en modo CBC con padding ISO7816d4
		final BufferedBlockCipher encryptCipher = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
				new AESEngine()
			),
			new ISO7816d4Padding()
		);
		// Creamos los parametros de cifrado con el vector de inicializacion (iv)
		final ParametersWithIV parameterIV = new ParametersWithIV(
			new KeyParameter(aesKey),
			iv
		);
		// Inicializamos
		encryptCipher.init(true, parameterIV);

		// Buffers para mover octetos de un flujo a otro
		final byte[] buf = new byte[16]; // Buffer de entrada
		final byte[] obuf = new byte[512]; // Buffer de salida

		try (
			final InputStream bin = new ByteArrayInputStream(testBytes);
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
			tmp = bout.toByteArray();
			System.out.println(HexUtils.hexify(tmp, false));
		}

	}

	/** Pruebas de cifrado de un solo bloque AES.
	 * @throws Exception En cualquier error. */
	@Test
	@Ignore
	@SuppressWarnings("static-method")
	public void testRawAes() throws Exception {

		// Primero con JSE
		final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding"); //$NON-NLS-1$
		System.out.println(cipher.getClass().getName());

		final byte[] aesKey = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
		};
		final SecretKey originalKey = new SecretKeySpec(aesKey, "AES"); //$NON-NLS-1$
		cipher.init(Cipher.ENCRYPT_MODE, originalKey);

		final byte[] res = cipher.doFinal(aesKey);
		System.out.println(HexUtils.hexify(res, false));

		System.out.println();

		// Ahora con BouncyCastle
		final byte[] s = new byte[16];
		final KeyParameter encKey = new KeyParameter(aesKey);
		final BlockCipher bCipher = new AESEngine();
		bCipher.init(true, encKey);
		bCipher.processBlock(aesKey, 0, s, 0);
		System.out.println(HexUtils.hexify(s, false));
	}

	/** Prueba de la generaci&oacute;n de un par de claves de curva el&iacute;ptica.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testEcKeyPairGeneration() throws Exception {
		final KeyPair kp = CH.generateEcKeyPair(EcCurve.BRAINPOOL_P256_R1);
		System.out.println(kp);
	}

	/** Prueba de cifrado DES ECB sin relleno.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDes() throws Exception {
		final byte[] key = "12345678".getBytes(); //$NON-NLS-1$
		final byte[] indata = "8765432123456789".getBytes(); //$NON-NLS-1$

		final byte[] c1 = new BcCryptoHelper().desEncrypt(indata, key);
		final byte[] c2 = new BcCryptoHelper().desEncrypt(indata, key);

		System.out.println(HexUtils.hexify(c1, false));
		System.out.println(HexUtils.hexify(c2, false));

		final byte[] c3 = new BcCryptoHelper().desDecrypt(c2, key);
		final byte[] c4 = new BcCryptoHelper().desDecrypt(c1, key);

		System.out.println(new String(c3));
		System.out.println(new String(c4));

		Assert.assertTrue(HexUtils.arrayEquals(c3, c4));
		Assert.assertTrue(HexUtils.arrayEquals(indata, c4));
	}

	/** Prueba de cifrado 3DES CBC sin relleno.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDesede() throws Exception {
		final byte[] key = "12345678abcdefgh".getBytes(); //$NON-NLS-1$
		final byte[] indata = "8765432123456789".getBytes(); //$NON-NLS-1$

		final byte[] c1 = new BcCryptoHelper().desedeEncrypt(indata, key);
		final byte[] c2 = new BcCryptoHelper().desedeEncrypt(indata, key);

		System.out.println(HexUtils.hexify(c1, false));
		System.out.println(HexUtils.hexify(c2, false));

		final byte[] c3 = new BcCryptoHelper().desedeDecrypt(c2, key);
		final byte[] c4 = new BcCryptoHelper().desedeDecrypt(c1, key);

		System.out.println(new String(c3));
		System.out.println(new String(c4));

//		Assert.assertTrue(HexUtils.arrayEquals(c3, c4));
//		Assert.assertTrue(HexUtils.arrayEquals(indata, c4));
	}

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final KeyPairGenerator kpg = new KeyPairGeneratorSpi.ECDH();
		final AlgorithmParameterSpec parameterSpec = new ECNamedCurveGenParameterSpec(
			EcCurve.BRAINPOOL_P256_R1.toString()
		);
		kpg.initialize(parameterSpec);
		final KeyPair kp = kpg.generateKeyPair();

		System.out.println(kp);

//		final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
//		System.out.println(cipher.getClass().getName());
//		final Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
//		System.out.println(dec.getClass().getName());
//		System.out.println(dec.getProvider());

		final KeyAgreement ka = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
		System.out.println(ka.getClass().getName());

	}

	private static final byte[] RSA_TEST_DATA = {
		(byte) 0x11, (byte) 0xD3, (byte) 0x74, (byte) 0x2F, (byte) 0xD0, (byte) 0xF4, (byte) 0xCF, (byte) 0x2E, (byte) 0x28, (byte) 0xD8, (byte) 0x77, (byte) 0x1C, (byte) 0x84, (byte) 0x54, (byte) 0xB5, (byte) 0xED,
		(byte) 0xE7, (byte) 0xE0, (byte) 0xC9, (byte) 0xD6, (byte) 0x33, (byte) 0x69, (byte) 0x9E, (byte) 0x31, (byte) 0x61, (byte) 0xBC, (byte) 0x91, (byte) 0x53, (byte) 0xEB, (byte) 0x99, (byte) 0x1D, (byte) 0xAB,
		(byte) 0xEB, (byte) 0x88, (byte) 0x5A, (byte) 0xEE, (byte) 0xD8, (byte) 0xAE, (byte) 0xBE, (byte) 0x34, (byte) 0x19, (byte) 0xB5, (byte) 0x29, (byte) 0x3E, (byte) 0x15, (byte) 0xCD, (byte) 0x59, (byte) 0xF3,
		(byte) 0x1D, (byte) 0xC7, (byte) 0x9D, (byte) 0xBB, (byte) 0x2D, (byte) 0x4B, (byte) 0xA9, (byte) 0xAF, (byte) 0x2B, (byte) 0x17, (byte) 0x61, (byte) 0xF3, (byte) 0x86, (byte) 0x4A, (byte) 0x23, (byte) 0x4E,
		(byte) 0xE6, (byte) 0x41, (byte) 0xA6, (byte) 0xE8, (byte) 0x49, (byte) 0x94, (byte) 0x75, (byte) 0xC2, (byte) 0xD3, (byte) 0x69, (byte) 0x26, (byte) 0xD0, (byte) 0x59, (byte) 0xED, (byte) 0xA7, (byte) 0x09,
		(byte) 0x54, (byte) 0x63, (byte) 0xB3, (byte) 0xE7, (byte) 0xD7, (byte) 0x70, (byte) 0xE8, (byte) 0xE7, (byte) 0x95, (byte) 0x89, (byte) 0x80, (byte) 0x76, (byte) 0x58, (byte) 0xD6, (byte) 0x10, (byte) 0x23,
		(byte) 0x80, (byte) 0xE1, (byte) 0x96, (byte) 0xB0, (byte) 0x6F, (byte) 0x05, (byte) 0x05, (byte) 0x56, (byte) 0x07, (byte) 0x00, (byte) 0x2E, (byte) 0xBE, (byte) 0x6E, (byte) 0xCF, (byte) 0x25, (byte) 0xC0,
		(byte) 0x20, (byte) 0x6E, (byte) 0xB3, (byte) 0x7F, (byte) 0x91, (byte) 0xED, (byte) 0xC8, (byte) 0x5D, (byte) 0x24, (byte) 0x55, (byte) 0x59, (byte) 0x49, (byte) 0xA8, (byte) 0xF9, (byte) 0x2A, (byte) 0x2D
	};

    /** Clave privada RSA para pruebas. */
	private static final RSAPrivateKey RSA_TEST_PRIVATE_KEY = new RSAPrivateKey() {

        private static final long serialVersionUID = 6991556885804507378L;

        @Override
		public String toString() {
        	return "Clave privada RSA para pruebas"; //$NON-NLS-1$
        }

        private final BigInteger ifdModulus = new BigInteger(1, new byte[] {
            (byte) 0xF4, (byte) 0x27, (byte) 0x97, (byte) 0x8D, (byte) 0xA1, (byte) 0x59, (byte) 0xBA, (byte) 0x02,
            (byte) 0x79, (byte) 0x30, (byte) 0x8A, (byte) 0x6C, (byte) 0x6A, (byte) 0x89, (byte) 0x50, (byte) 0x5A,
            (byte) 0xDA, (byte) 0x5A, (byte) 0x67, (byte) 0xC3, (byte) 0xDA, (byte) 0x26, (byte) 0x79, (byte) 0xEA,
            (byte) 0xF4, (byte) 0xA1, (byte) 0xB0, (byte) 0x11, (byte) 0x9E, (byte) 0xDD, (byte) 0x4D, (byte) 0xF4,
            (byte) 0x6E, (byte) 0x78, (byte) 0x04, (byte) 0x24, (byte) 0x71, (byte) 0xA9, (byte) 0xD1, (byte) 0x30,
            (byte) 0x1D, (byte) 0x3F, (byte) 0xB2, (byte) 0x8F, (byte) 0x38, (byte) 0xC5, (byte) 0x7D, (byte) 0x08,
            (byte) 0x89, (byte) 0xF7, (byte) 0x31, (byte) 0xDB, (byte) 0x8E, (byte) 0xDD, (byte) 0xBC, (byte) 0x13,
            (byte) 0x67, (byte) 0xC1, (byte) 0x34, (byte) 0xE1, (byte) 0xE9, (byte) 0x47, (byte) 0x78, (byte) 0x6B,
            (byte) 0x8E, (byte) 0xC8, (byte) 0xE4, (byte) 0xB9, (byte) 0xCA, (byte) 0x6A, (byte) 0xA7, (byte) 0xC2,
            (byte) 0x4C, (byte) 0x86, (byte) 0x91, (byte) 0xC7, (byte) 0xBE, (byte) 0x2F, (byte) 0xD8, (byte) 0xC1,
            (byte) 0x23, (byte) 0x66, (byte) 0x0E, (byte) 0x98, (byte) 0x65, (byte) 0xE1, (byte) 0x4F, (byte) 0x19,
            (byte) 0xDF, (byte) 0xFB, (byte) 0xB7, (byte) 0xFF, (byte) 0x38, (byte) 0x08, (byte) 0xC9, (byte) 0xF2,
            (byte) 0x04, (byte) 0xE7, (byte) 0x97, (byte) 0xD0, (byte) 0x6D, (byte) 0xD8, (byte) 0x33, (byte) 0x3A,
            (byte) 0xC5, (byte) 0x83, (byte) 0x86, (byte) 0xEE, (byte) 0x4E, (byte) 0xB6, (byte) 0x1E, (byte) 0x20,
            (byte) 0xEC, (byte) 0xA7, (byte) 0xEF, (byte) 0x38, (byte) 0xD5, (byte) 0xB0, (byte) 0x5E, (byte) 0xB1,
            (byte) 0x15, (byte) 0x96, (byte) 0x6A, (byte) 0x5A, (byte) 0x89, (byte) 0xAD, (byte) 0x58, (byte) 0xA5
        });

        private final BigInteger ifdPrivateExponent = new BigInteger(1, new byte[] {
            (byte) 0xD2, (byte) 0x7A, (byte) 0x03, (byte) 0x23, (byte) 0x7C, (byte) 0x72, (byte) 0x2E, (byte) 0x71,
            (byte) 0x8D, (byte) 0x69, (byte) 0xF4, (byte) 0x1A, (byte) 0xEC, (byte) 0x68, (byte) 0xBD, (byte) 0x95,
            (byte) 0xE4, (byte) 0xE0, (byte) 0xC4, (byte) 0xCD, (byte) 0x49, (byte) 0x15, (byte) 0x9C, (byte) 0x4A,
            (byte) 0x99, (byte) 0x63, (byte) 0x7D, (byte) 0xB6, (byte) 0x62, (byte) 0xFE, (byte) 0xA3, (byte) 0x02,
            (byte) 0x51, (byte) 0xED, (byte) 0x32, (byte) 0x9C, (byte) 0xFC, (byte) 0x43, (byte) 0x89, (byte) 0xEB,
            (byte) 0x71, (byte) 0x7B, (byte) 0x85, (byte) 0x02, (byte) 0x04, (byte) 0xCD, (byte) 0xF3, (byte) 0x30,
            (byte) 0xD6, (byte) 0x46, (byte) 0xFC, (byte) 0x7B, (byte) 0x2B, (byte) 0x19, (byte) 0x29, (byte) 0xD6,
            (byte) 0x8C, (byte) 0xBE, (byte) 0x39, (byte) 0x49, (byte) 0x7B, (byte) 0x62, (byte) 0x3A, (byte) 0x82,
            (byte) 0xC7, (byte) 0x64, (byte) 0x1A, (byte) 0xC3, (byte) 0x48, (byte) 0x79, (byte) 0x57, (byte) 0x3D,
            (byte) 0xEA, (byte) 0x0D, (byte) 0xAB, (byte) 0xC7, (byte) 0xCA, (byte) 0x30, (byte) 0x9A, (byte) 0xE4,
            (byte) 0xB3, (byte) 0xED, (byte) 0xDA, (byte) 0xFA, (byte) 0xEE, (byte) 0x55, (byte) 0xD5, (byte) 0x42,
            (byte) 0xF7, (byte) 0x80, (byte) 0x23, (byte) 0x03, (byte) 0x51, (byte) 0xE7, (byte) 0x5E, (byte) 0x7F,
            (byte) 0x32, (byte) 0xDC, (byte) 0x65, (byte) 0x2E, (byte) 0xF1, (byte) 0xED, (byte) 0x47, (byte) 0xA5,
            (byte) 0x1C, (byte) 0x18, (byte) 0xD9, (byte) 0xDF, (byte) 0x9F, (byte) 0xF4, (byte) 0x8D, (byte) 0x87,
            (byte) 0x8D, (byte) 0xB6, (byte) 0x22, (byte) 0xEA, (byte) 0x6E, (byte) 0x93, (byte) 0x70, (byte) 0xE9,
            (byte) 0xC6, (byte) 0x3B, (byte) 0x35, (byte) 0x8B, (byte) 0x7C, (byte) 0x11, (byte) 0x5A, (byte) 0xA1
        });

        @Override
        public BigInteger getModulus() {
            return ifdModulus;
        }

        @Override
        public String getFormat() {
            return "PKCS#8"; //$NON-NLS-1$
        }

        @Override
        public byte[] getEncoded() {
        	throw new UnsupportedOperationException();
        }

        @Override
        public String getAlgorithm() {
            return "RSA"; //$NON-NLS-1$
        }

        @Override
        public BigInteger getPrivateExponent() {
            return ifdPrivateExponent;
        }
    };

	/** Prueba de firmas RSA de JSE vs. BC.
	 * @throws IOException En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testRsa() throws IOException {
		final byte[] res1 = doRsaJca(RSA_TEST_DATA, RSA_TEST_PRIVATE_KEY);
		System.out.println("Resultado con JCA: " + HexUtils.hexify(res1, false)); //$NON-NLS-1$
		final byte[] res2 = doRsaBc(RSA_TEST_DATA, RSA_TEST_PRIVATE_KEY);
		System.out.println("Resultado con BC:  " + HexUtils.hexify(res2, false)); //$NON-NLS-1$
		Assert.assertArrayEquals(res1, res2);
	}

	private static byte[] doRsaBc(final byte[] data, final RSAKey key) throws IOException {
    	final boolean forEncryption = true;

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

	private static byte[] doRsaJca(final byte[] data, final RSAKey key) throws IOException {
    	final int direction = Cipher.ENCRYPT_MODE;
        try {
            final Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING"); //$NON-NLS-1$
            dec.init(direction, (Key) key);
            return dec.doFinal(data);
        }
        catch (final NoSuchAlgorithmException  |
        		     NoSuchPaddingException    |
        		     InvalidKeyException       |
        		     IllegalBlockSizeException |
        		     BadPaddingException e) {
            throw new IOException(
        		"Error cifrando / descifrando datos mediante RSA", e //$NON-NLS-1$
    		);
        }
	}

	private static byte[] do3DesJca(final byte[] data, final byte[] key) throws IOException {
        final byte[] ivBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            ivBytes[i] = 0x00;
        }

        final SecretKey k = new SecretKeySpec(prepareDesedeKey(key), "DESede"); //$NON-NLS-1$
        try {
            final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding"); //$NON-NLS-1$
            cipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(ivBytes));
            return cipher.doFinal(data);
        }
        catch (final NoSuchAlgorithmException           |
        		     NoSuchPaddingException             |
        		     InvalidKeyException                |
        		     InvalidAlgorithmParameterException |
        		     IllegalBlockSizeException          |
        		     BadPaddingException e) {
            throw new IOException("Error encriptando datos", e); //$NON-NLS-1$
        }
        finally {
            // Machacamos los datos para evitar que queden en memoria
            for(int i=0;i<data.length;i++) {
                data[i] = '\0';
            }
        }
	}

	private static byte[] do3DesBc(final byte[] data, final byte[] key) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
		final BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
		cipher.init(true, new KeyParameter(key));
		final byte[] result = new byte[cipher.getOutputSize(data.length)];
		final int tam = cipher.processBytes(data, 0, data.length, result, 0);
		cipher.doFinal(result, tam);
		return result;
	}

	/** Pruebas 3DES BouncyCastle vs JCE.
	 * @throws Exception Si falla el 3DES. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void test3Des() throws Exception {
		final byte[] key = {
			(byte) 0xE0, (byte) 0x35, (byte) 0x76, (byte) 0xA0, (byte) 0x62, (byte) 0x53, (byte) 0x87, (byte) 0x36,
			(byte) 0xD4, (byte) 0x37, (byte) 0xA1, (byte) 0x64, (byte) 0xFE, (byte) 0x72, (byte) 0x19, (byte) 0x0D,
			(byte) 0xE0, (byte) 0x35, (byte) 0x76, (byte) 0xA0, (byte) 0x62, (byte) 0x53, (byte) 0x87, (byte) 0x36
		};
		final byte[] data = new byte[224];
		new SecureRandom().nextBytes(data);
		//System.out.println(HexUtils.hexify(data, false));
		final byte[] res1 = do3DesBc(data, key);
		final byte[] res2 = do3DesJca(data, key);
		System.out.println(HexUtils.hexify(res1, false));
		System.out.println(HexUtils.hexify(res2, false));
		Assert.assertTrue(HexUtils.arrayEquals(res1, res2));
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

    /** Pruebas de generaci&oaccute;n dee certificados.
     * @throws Exception En cualquier error. */
    @SuppressWarnings("static-method")
	@Test
    public void testCertFactory() throws Exception {
    	final Provider p = new BouncyCastleProvider();
    	Security.insertProviderAt(p, 1);
    	final CertificateFactory cf = CertificateFactory.getInstance("X.509", p);
    	System.out.println(cf.getClass().getName());
    	final CertificateFactorySpi cfspi = new org.spongycastle.jcajce.provider.asymmetric.x509.CertificateFactory();

    }

}
