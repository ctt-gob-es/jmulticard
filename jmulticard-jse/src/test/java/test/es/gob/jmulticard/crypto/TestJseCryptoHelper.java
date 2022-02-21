package test.es.gob.jmulticard.crypto;

import java.security.Security;

import org.junit.Test;
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



}
