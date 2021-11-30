package test.es.gob.jmulticard;

import java.security.KeyPair;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.JseCryptoHelper;

/** Pruebas de las operaciones criptogr&aacute;ficas en JSE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestJseCryptoHelper {

	/** Prueba de la generaci&oacute;n de un par de claves de curva el&iacute;ptica.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testEcKeyPairGeneration() throws Exception {
		final KeyPair kp = new JseCryptoHelper().generateEcKeyPair(es.gob.jmulticard.CryptoHelper.EcCurve.BRAINPOOL_P256_R1);
		System.out.println(kp);
	}

}
