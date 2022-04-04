package test.es.gob.jmulticard.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.ISO7816d4Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveGenParameterSpec;

import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.EcCurve;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;


/** Pruebas de operaciones criptogr&aacute;ficas con JseCryptoHelper.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestCryptoHelper {

	private static final CryptoHelper CH = new JseCryptoHelper();

	/** Pruebas de cifrado AES.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
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
		final byte[] in = new JseCryptoHelper().aesEncrypt(
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

		int noBytesRead = 0; // Numero de octetos leidos de la entrada
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
		int noBytesRead = 0; // Numero de octetos leidos de la entrada
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
	public void testDes() throws Exception {
		final byte[] key = "12345678".getBytes(); //$NON-NLS-1$
		final byte[] indata = "8765432123456789".getBytes(); //$NON-NLS-1$

		final byte[] c1 = new JseCryptoHelper().desEncrypt(indata, key);
		final byte[] c2 = new BcCryptoHelper().desEncrypt(indata, key);

		System.out.println(HexUtils.hexify(c1, false));
		System.out.println(HexUtils.hexify(c2, false));

		final byte[] c3 = new JseCryptoHelper().desDecrypt(c2, key);
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
	public void testDesede() throws Exception {
		final byte[] key = "12345678abcdefgh".getBytes(); //$NON-NLS-1$
		final byte[] indata = "8765432123456789".getBytes(); //$NON-NLS-1$

		final byte[] c1 = new JseCryptoHelper().desedeEncrypt(indata, key);
		final byte[] c2 = new BcCryptoHelper().desedeEncrypt(indata, key);

		System.out.println(HexUtils.hexify(c1, false));
		System.out.println(HexUtils.hexify(c2, false));

		final byte[] c3 = new JseCryptoHelper().desedeDecrypt(c2, key);
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

		//System.out.println(kp);

//		final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
//		System.out.println(cipher.getClass().getName());
//		final Cipher dec = Cipher.getInstance("RSA/ECB/NOPADDING", BouncyCastleProvider.PROVIDER_NAME); //$NON-NLS-1$
//		System.out.println(dec.getClass().getName());
//		System.out.println(dec.getProvider());

		final KeyAgreement ka = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
		System.out.println(ka.getClass().getName());

	}

}
