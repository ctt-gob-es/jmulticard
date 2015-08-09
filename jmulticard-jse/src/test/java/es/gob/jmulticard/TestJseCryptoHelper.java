package es.gob.jmulticard;

import java.security.KeyPair;

import org.junit.Test;

import es.gob.jmulticard.CryptoHelper.EcCurve;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;

/** Pruebas de las operaciones criptogr&aacute;ficas en JSE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestJseCryptoHelper {

	/** Prueba de la generaci&oacute;n de un par de claves de curva el&iacute;ptica.
	 * @throws Exception EN cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testEcKeyPairGeneration() throws Exception {
		final KeyPair kp = new JseCryptoHelper().generateEcKeyPair(EcCurve.BRAINPOOL_P256_R1);
		System.out.println(kp);
	}

}
