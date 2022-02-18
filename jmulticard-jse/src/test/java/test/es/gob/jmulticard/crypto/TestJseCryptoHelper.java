package test.es.gob.jmulticard.crypto;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.JseCryptoHelper;

/** Pruebas de operaciones criptogr&aacute;ficas con JseCryptoHelper.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestJseCryptoHelper {

	private static final CryptoHelper CH = new JseCryptoHelper();

	/** Pruebas de CMAC con AES.
	 * @throws Exception EN cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testAesCmac() throws Exception {
		CH.doAesCmac(null, null);

	}



}
