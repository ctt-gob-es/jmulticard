package es.gob.jmulticard;

import javax.security.auth.callback.PasswordCallback;

import org.junit.Test;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de cambio de PIN.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestDnieChangePIN {

	final static class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Contruye una <i>Callback</i> con una contrase&ntilde; preestablecida.
	     * @param password Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        setPassword(password);
	    }
	}

	/** Llamada a las pruebas a ejecutar
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		TestDnieChangePIN.testChangePIN();
	}

	/** Test para probar el cambio de PIN tras la apertura del canal seguro.
	 * @throws Exception En cualquier error. */
	@Test
	public static void testChangePIN() throws Exception {
		final CachePasswordCallback cpc = new CachePasswordCallback("password".toCharArray()); //$NON-NLS-1$
		final ApduConnection ac = new SmartcardIoConnection();
		final Dnie dni = DnieFactory.getDnie(ac , cpc, new JseCryptoHelper(), null);
		dni.changePIN("password", "pinNuevo"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
