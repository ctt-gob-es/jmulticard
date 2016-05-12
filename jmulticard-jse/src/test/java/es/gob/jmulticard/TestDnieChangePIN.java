package es.gob.jmulticard;

import org.junit.Test;

import es.gob.jmulticard.TestCeres.CachePasswordCallback;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de cambio de PIN.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestDnieChangePIN {

	/**
	 * Llamada a los test a ejecutar
	 * @param args
	 * @throws Exception
	 */
	public static void main(final String[] args) throws Exception {
		TestDnieChangePIN.testChangePIN();
	}
	/**
	 * Test para probar el cambio de PIN tras la apertura del canal seguro
	 * @throws Exception
	 */
	@Test
	public static void testChangePIN() throws Exception {
		final CachePasswordCallback cpc = new CachePasswordCallback("password".toCharArray()); //$NON-NLS-1$
		final ApduConnection ac = new SmartcardIoConnection();
		final CryptoCard dni = DnieFactory.getDnie(ac , cpc, new JseCryptoHelper(), null);
		dni.changePIN("password", "pinNuevo"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
