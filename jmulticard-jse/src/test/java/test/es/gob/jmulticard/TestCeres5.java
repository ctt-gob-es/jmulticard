package test.es.gob.jmulticard;

import es.gob.jmulticard.card.dnie.ceressc.CeresSc5;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de tarjetas FNMT CERES v5 con canal EAC 2.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestCeres5 {

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final ApduConnection conn = new SmartcardIoConnection();
		final CeresSc5 card = new CeresSc5(
			conn,
			null, // PasswordCallback
			new BcCryptoHelper(),
			new TestingDnieCallbackHandler(null, "CRYPTOKIFNMT".toCharArray()) //$NON-NLS-1$
		);
		System.out.println(card);
	}
}
