package test.es.gob.jmulticard.crypto;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;

/** Pruebas de operaciones criptogr&aacute;ficas con JseCryptoHelper.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestJseCryptoHelper {

	private static final CryptoHelper CH = new JseCryptoHelper();

	/** Pruebas de CMAC con AES.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testAes() throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		final String testString = "prueb"; //$NON-NLS-1$
		final byte[] testBytes = testString.getBytes();
		final byte[] aesKey = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00
		};
		final byte[] iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		System.out.println(testString);
		byte[] tmp = CH.aesEncrypt(
			testBytes,
			iv,
			aesKey,
			"ISO7816-4Padding" //$NON-NLS-1$
		);
		System.out.println(
			HexUtils.hexify(tmp, false)
		);
		tmp = CH.aesDecrypt(
			tmp,
			iv,
			aesKey,
			"ISO7816-4Padding" //$NON-NLS-1$
		);
		System.out.println(new String(tmp));

		System.out.println();

	}

	/** Pruebas de cifrado de un solo bloque AES.
	 * @throws Exception En cualquier error. */
	@Test
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



}
